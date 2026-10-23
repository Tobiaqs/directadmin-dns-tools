#!/usr/bin/env python3
"""Manage DirectAdmin Login Keys (API tokens) from the command line.

Credentials file format (default: credentials.txt next to this script):
    line 1: DirectAdmin URL, e.g. https://da590.myhost.de:2222
    line 2: username
    line 3: password

Examples:
    ./da_login_keys.py list
    ./da_login_keys.py create dnskey --cmd CMD_API_DNS_CONTROL
    ./da_login_keys.py create acme --cmd CMD_API_DNS_CONTROL --ip 1.2.3.4 --expires "2027-01-01 00:00"
    ./da_login_keys.py delete dnskey
    ./da_login_keys.py test dnskey-token-file-or-value --domain wildhorse.com
"""
import argparse
import base64
import getpass
import json
import os
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


def load_credentials(path):
    try:
        with open(path) as f:
            lines = [l.strip() for l in f.read().splitlines()]
    except FileNotFoundError:
        sys.exit(f"Credentials file not found: {path}")
    if len(lines) < 2:
        sys.exit("Credentials file needs at least URL and username (password is prompted if missing)")
    url, user = lines[0].rstrip("/"), lines[1]
    password = lines[2] if len(lines) > 2 and lines[2] else getpass.getpass(f"Password for {user}: ")
    return url, user, password


def call(base, user, secret, cmd, data=None, query=None):
    url = f"{base}/{cmd}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    body = urllib.parse.urlencode(data, doseq=True).encode() if data is not None else None
    req = urllib.request.Request(url, data=body)
    auth = base64.b64encode(f"{user}:{secret}".encode()).decode()
    req.add_header("Authorization", f"Basic {auth}")
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: {e.read().decode(errors='replace')[:500]}")


def parse_qs(text):
    return {k: v[0] for k, v in urllib.parse.parse_qs(text, keep_blank_values=True).items()}


def check(resp):
    r = parse_qs(resp)
    if r.get("error") != "0":
        sys.exit(f"Error: {r.get('text', '')} {r.get('details', '')}".strip())
    return r


def fmt_ts(ts):
    if not ts or ts == "0":
        return "never"
    return datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")


def key_permissions(base, user, pw, name):
    """Return (allowed, denied) command lists; DA only exposes these via show_modify tables."""
    r = parse_qs(call(base, user, pw, "CMD_API_LOGIN_KEYS", query={"action": "show_modify", "keyname": name}))
    result = []
    for table, field in (("allow_table", "allow"), ("deny_table", "deny")):
        cmds = []
        for row in parse_qs(r.get(table, "")).values():
            cell = parse_qs(row)
            if cell.get("checkbox") == "checked" and field in cell:
                cmds.append(cell[field])
        result.append(sorted(cmds))
    return tuple(result)


def cmd_list(args, base, user, pw):
    resp = call(base, user, pw, "CMD_API_LOGIN_KEYS", query={"json": "yes"})
    keys = json.loads(resp)
    if not keys:
        print("No login keys.")
        return
    for name, raw in keys.items():
        k = parse_qs(raw)
        print(f"{name}")
        print(f"  created:  {fmt_ts(k.get('date_created'))} from {k.get('created_by', '?')}")
        print(f"  expires:  {fmt_ts(k.get('expiry'))}")
        print(f"  uses:     {k.get('uses', '0')} / {k.get('max_uses', '0') if k.get('max_uses') != '0' else 'unlimited'}")
        allowed, denied = key_permissions(base, user, pw, name)
        print(f"  allowed:  {', '.join(allowed) if allowed else 'ALL (full access)'}")
        if denied:
            print(f"  denied:   {', '.join(denied)}")
        if args.verbose:
            for kk, v in sorted(k.items()):
                print(f"    {kk} = {v}")


def cmd_create(args, base, user, pw):
    key = args.key or secrets.token_hex(32)
    data = {
        "action": "create",
        "keyname": args.name,
        "key": key,
        "key2": key,
        "max_uses": str(args.max_uses),
        "clear_key": "yes" if args.clear_key else "no",
        "allow_html": "no",
        "passwd": pw,
    }
    if args.expires:
        try:
            dt = datetime.strptime(args.expires, "%Y-%m-%d %H:%M")
        except ValueError:
            sys.exit('--expires must look like "YYYY-MM-DD HH:MM"')
        data.update(never_expires="no", year=dt.year, month=dt.month, day=dt.day, hour=dt.hour, minute=dt.minute)
    else:
        data["never_expires"] = "yes"
    for i, c in enumerate(args.cmd or []):
        data[f"select_allow{i}"] = c
    for i, c in enumerate(args.deny or []):
        data[f"select_deny{i}"] = c
    if args.ip:
        data["ips"] = "\n".join(args.ip)
    check(call(base, user, pw, "CMD_API_LOGIN_KEYS", data=data))
    if args.out:
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(key + "\n")
        print(f"Key '{args.name}' created; value written to {args.out}")
    else:
        print(f"Key '{args.name}' created. Value (store it now, it cannot be shown again):")
        print(key)
    if not args.cmd:
        print("WARNING: no --cmd given, this key has FULL access to the account.", file=sys.stderr)


def cmd_delete(args, base, user, pw):
    data = {"action": "select", "delete": "yes"}
    for i, n in enumerate(args.names):
        data[f"select{i}"] = n
    check(call(base, user, pw, "CMD_API_LOGIN_KEYS", data=data))
    print(f"Deleted: {', '.join(args.names)}")


def cmd_test(args, base, user, pw):
    key = args.key
    if os.path.isfile(key):
        with open(key) as f:
            key = f.read().strip()
    resp = call(base, user, key, "CMD_API_DNS_CONTROL", query={"domain": args.domain, "json": "yes"})
    try:
        records = json.loads(resp).get("records", [])
        print(f"OK: key can read DNS for {args.domain} ({len(records)} records)")
    except json.JSONDecodeError:
        print(f"Failed: {parse_qs(resp).get('text', resp[:200])}")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(description="Manage DirectAdmin Login Keys")
    p.add_argument("-c", "--credentials", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials.txt"))
    sub = p.add_subparsers(dest="action", required=True)

    s = sub.add_parser("list", help="list login keys")
    s.add_argument("-v", "--verbose", action="store_true", help="show all raw fields")
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("create", help="create a login key")
    s.add_argument("name", help="key name (letters/digits only)")
    s.add_argument("--cmd", action="append", help="allowed command, repeatable (e.g. CMD_API_DNS_CONTROL). Omit = full access!")
    s.add_argument("--deny", action="append", help="denied command, repeatable")
    s.add_argument("--ip", action="append", help="allowed source IP, repeatable (default: any)")
    s.add_argument("--expires", help='expiry as "YYYY-MM-DD HH:MM" (default: never)')
    s.add_argument("--max-uses", type=int, default=0, help="0 = unlimited (default)")
    s.add_argument("--clear-key", action="store_true", help="delete key automatically once expired/used up")
    s.add_argument("--key", help="use this key value instead of a random one")
    s.add_argument("-o", "--out", help="write key value to this file (mode 600) instead of printing")
    s.set_defaults(func=cmd_create)

    s = sub.add_parser("delete", help="delete one or more login keys")
    s.add_argument("names", nargs="+")
    s.set_defaults(func=cmd_delete)

    s = sub.add_parser("test", help="check a key can read DNS for a domain")
    s.add_argument("key", help="key value or path to file containing it")
    s.add_argument("--domain", required=True)
    s.set_defaults(func=cmd_test)

    args = p.parse_args()
    base, user, pw = load_credentials(args.credentials)
    args.func(args, base, user, pw)


if __name__ == "__main__":
    main()
