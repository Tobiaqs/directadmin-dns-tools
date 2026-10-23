#!/usr/bin/env python3
"""Manage DNS records on a DirectAdmin account using a Login Key.

Authentication:
    URL and username come from lines 1 and 2 of the credentials file
    (default: credentials.txt next to this script). The secret is the login key
    read from --key-file (default: dns_token.txt next to this script), or the
    DA_KEY environment variable if set.

Names: use a relative name ("www", "_acme-challenge") or a fully qualified
name with a trailing dot ("wildhorse.com."). "@" means the domain apex.

Examples:
    ./da_dns.py -d wildhorse.com list
    ./da_dns.py -d wildhorse.com list --type TXT
    ./da_dns.py -d wildhorse.com add A test 1.2.3.4
    ./da_dns.py -d wildhorse.com add TXT _acme-challenge "some-token"
    ./da_dns.py -d wildhorse.com add MX @ "10 mail.example.com."
    ./da_dns.py -d wildhorse.com set A test 5.6.7.8      # replaces all A records for 'test'
    ./da_dns.py -d wildhorse.com delete A test            # deletes all A records for 'test'
    ./da_dns.py -d wildhorse.com delete TXT _acme-challenge "some-token"
    ./da_dns.py -d wildhorse.com export > wildhorse.com.zone.txt
    ./da_dns.py -d wildhorse.com ttl 600                  # zone-wide TTL ("default" to reset)
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "PTR", "SRV", "CAA", "TLSA", "DS"]


class DA:
    def __init__(self, base, user, key):
        self.base, self.user, self.key = base.rstrip("/"), user, key

    def call(self, query=None, data=None):
        url = f"{self.base}/CMD_API_DNS_CONTROL"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body)
        auth = base64.b64encode(f"{self.user}:{self.key}".encode()).decode()
        req.add_header("Authorization", f"Basic {auth}")
        try:
            with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as r:
                return r.read().decode()
        except urllib.error.HTTPError as e:
            sys.exit(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}")

    def records(self, domain):
        resp = self.call(query={"domain": domain, "json": "yes"})
        try:
            return json.loads(resp)["records"]
        except (json.JSONDecodeError, KeyError):
            sys.exit(f"Error: {result_text(resp)}")

    def post(self, data):
        resp = self.call(data=dict(data, json="yes"))
        try:
            r = json.loads(resp)
        except json.JSONDecodeError:
            r = {k: v[0] for k, v in urllib.parse.parse_qs(resp).items()}
        if str(r.get("error", "0")) != "0":
            sys.exit(f"Error: {r.get('result') or r.get('text', '')} {r.get('details', '')}".strip())
        return r


def result_text(resp):
    r = {k: v[0] for k, v in urllib.parse.parse_qs(resp).items()}
    return f"{r.get('text', resp[:200])} {r.get('details', '')}".strip()


def norm_name(name, domain):
    """Normalise to DirectAdmin's form: relative names stay relative, apex becomes 'domain.'."""
    if name in ("@", domain, domain + "."):
        return domain + "."
    if name.endswith("." + domain + "."):
        return name[: -len(domain) - 2]
    if name.endswith("." + domain):
        return name[: -len(domain) - 1]
    return name


def find(records, rtype, name, value=None):
    out = [r for r in records if r["type"] == rtype and r["name"] == name]
    if value is not None:
        out = [r for r in out if r["value"] in (value, f'"{value}"')]
    return out


def add_record(da, domain, rtype, name, value, affect_pointers):
    data = {"domain": domain, "action": "add", "type": rtype, "name": name}
    if rtype == "MX":
        prio, _, host = value.partition(" ")
        if not prio.isdigit() or not host:
            sys.exit('MX value must look like "10 mail.example.com."')
        data.update(value=prio, mx_value=host)
    else:
        data["value"] = value
    if rtype in ("A", "AAAA"):
        data["affect_pointers"] = "yes" if affect_pointers else "no"
    da.post(data)


def delete_records(da, domain, recs):
    data = {"domain": domain, "action": "select", "delete": "yes"}
    for i, r in enumerate(recs):
        data[f"{r['type'].lower()}recs{i}"] = r["combined"]
    da.post(data)


def cmd_list(da, args):
    recs = da.records(args.domain)
    if args.type:
        recs = [r for r in recs if r["type"] == args.type.upper()]
    if args.name:
        recs = [r for r in recs if r["name"] == norm_name(args.name, args.domain)]
    if args.json:
        print(json.dumps([{k: r[k] for k in ("type", "name", "value")} for r in recs], indent=2))
        return
    w = max((len(r["name"]) for r in recs), default=4)
    for r in recs:
        print(f"{r['type']:<6} {r['name']:<{w}}  {r['value']}")


def cmd_export(da, args):
    for r in da.records(args.domain):
        name = r["name"] if r["name"].endswith(".") else f"{r['name']}.{args.domain}."
        print(f"{name}\tIN\t{r['type']}\t{r['value']}")


def cmd_add(da, args):
    rtype, name = args.type.upper(), norm_name(args.name, args.domain)
    if find(da.records(args.domain), rtype, name, args.value):
        print(f"Already exists: {rtype} {name} {args.value}")
        return
    add_record(da, args.domain, rtype, name, args.value, args.affect_pointers)
    print(f"Added: {rtype} {name} {args.value}")


def cmd_set(da, args):
    rtype, name = args.type.upper(), norm_name(args.name, args.domain)
    existing = find(da.records(args.domain), rtype, name)
    if len(existing) == 1 and existing[0]["value"] in (args.value, f'"{args.value}"'):
        print(f"Unchanged: {rtype} {name} {args.value}")
        return
    if existing:
        delete_records(da, args.domain, existing)
        for r in existing:
            print(f"Removed: {r['type']} {r['name']} {r['value']}")
    add_record(da, args.domain, rtype, name, args.value, args.affect_pointers)
    print(f"Added: {rtype} {name} {args.value}")


def cmd_delete(da, args):
    rtype, name = args.type.upper(), norm_name(args.name, args.domain)
    recs = find(da.records(args.domain), rtype, name, args.value)
    if not recs:
        sys.exit(f"No matching {rtype} record for {name}" + (f" with value {args.value}" if args.value else ""))
    if len(recs) > 1 and not args.yes and args.value is None:
        for r in recs:
            print(f"  {r['type']} {r['name']} {r['value']}")
        if input(f"Delete these {len(recs)} records? [y/N] ").strip().lower() != "y":
            sys.exit("Aborted.")
    delete_records(da, args.domain, recs)
    for r in recs:
        print(f"Deleted: {r['type']} {r['name']} {r['value']}")


def cmd_ttl(da, args):
    data = {"domain": args.domain, "action": "ttl"}
    if args.seconds == "default":
        data["ttl_select"] = "default"
    elif args.seconds.isdigit():
        data.update(ttl_select="custom", ttl=args.seconds)
    else:
        sys.exit('TTL must be a number of seconds or "default"')
    da.post(data)
    print(f"Zone TTL for {args.domain} set to {args.seconds}")


def load_auth(args):
    try:
        with open(args.credentials) as f:
            lines = [l.strip() for l in f.read().splitlines()]
    except FileNotFoundError:
        sys.exit(f"Credentials file not found: {args.credentials}")
    if len(lines) < 2:
        sys.exit("Credentials file needs the URL on line 1 and username on line 2")
    key = os.environ.get("DA_KEY")
    if not key:
        try:
            with open(args.key_file) as f:
                key = f.read().strip()
        except FileNotFoundError:
            sys.exit(f"Key file not found: {args.key_file} (or set DA_KEY)")
    return DA(lines[0], lines[1], key)


def main():
    p = argparse.ArgumentParser(description="Manage DirectAdmin DNS records")
    p.add_argument("-d", "--domain", required=True)
    p.add_argument("-c", "--credentials", default=os.path.join(HERE, "credentials.txt"))
    p.add_argument("-k", "--key-file", default=os.path.join(HERE, "dns_token.txt"))
    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("list", help="list records")
    s.add_argument("--type", choices=TYPES, type=str.upper)
    s.add_argument("--name")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("export", help="print records in zone-file-like format")
    s.set_defaults(func=cmd_export)

    for action, func, helptext in (("add", cmd_add, "add a record (no-op if it exists)"),
                                   ("set", cmd_set, "replace all records of this type+name with one value")):
        s = sub.add_parser(action, help=helptext)
        s.add_argument("type", choices=TYPES, type=str.upper)
        s.add_argument("name")
        s.add_argument("value")
        s.add_argument("--affect-pointers", action="store_true", help="A/AAAA: also create PTR records")
        s.set_defaults(func=func)

    s = sub.add_parser("delete", help="delete records (all of type+name, or only the given value)")
    s.add_argument("type", choices=TYPES, type=str.upper)
    s.add_argument("name")
    s.add_argument("value", nargs="?")
    s.add_argument("-y", "--yes", action="store_true", help="don't ask when deleting several records")
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("ttl", help="set the zone-wide TTL")
    s.add_argument("seconds", help='TTL in seconds, or "default" for the server default')
    s.set_defaults(func=cmd_ttl)

    args = p.parse_args()
    args.func(load_auth(args), args)


if __name__ == "__main__":
    main()
