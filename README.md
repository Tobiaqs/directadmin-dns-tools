# directadmin-dns-tools

Small Python scripts (standard library only, Python 3.6+) for managing DNS on a
DirectAdmin hosting account through its API:

- `da_login_keys.py` – create, list, test and delete DirectAdmin Login Keys (API tokens).
- `da_dns.py` – list, add, replace and delete DNS records using a Login Key.

The main use is getting Let's Encrypt certificates (including wildcards) with
certbot's DNS-01 challenge for domains whose DNS is hosted on DirectAdmin.

## Setup

### 1. Credentials file

Create `credentials.txt` next to the scripts:

```
https://da.example-host.com:2222
your-da-username
your-da-password
```

Line 3 (the password) is only used by `da_login_keys.py`; leave it out and
you will be prompted for it instead. `da_dns.py` only reads lines 1 and 2.

```sh
chmod 600 credentials.txt
```

`*.txt` is in `.gitignore`, so the credentials and key files are never committed.

### 2. Create a DNS-only Login Key

Create a key that can only call the DNS API, and write it to `dns_token.txt`
(created with mode 600):

```sh
./da_login_keys.py create certbot --cmd CMD_API_DNS_CONTROL -o dns_token.txt
```

Optional restrictions: `--ip 203.0.113.10` (repeatable) limits the key to the
server running certbot, `--expires "2027-01-01 00:00"` sets an expiry date.

Check that it works:

```sh
./da_login_keys.py test dns_token.txt --domain example.com
./da_dns.py -d example.com list --type TXT
```

After this the password can be removed from `credentials.txt`; `da_dns.py`
only needs the URL, username and the key.

## Using with certbot

Certbot's `manual` plugin can call a script to create the `_acme-challenge` TXT
record (`--manual-auth-hook`) and another to remove it afterwards
(`--manual-cleanup-hook`). Certbot passes the domain and token in the
environment variables `CERTBOT_DOMAIN` and `CERTBOT_VALIDATION`.

### Hook scripts

The repository includes two hook scripts:

- `certbot-auth.sh` – adds the `_acme-challenge` TXT record, then waits
  `DA_PROPAGATION_SECONDS` (default 60) for the DNS servers to pick it up.
- `certbot-cleanup.sh` – deletes that TXT record again.

They locate `da_dns.py` relative to their own path, so the repository can live
anywhere. The examples below assume `/opt/directadmin-dns-tools`.

Notes:

- The hooks use `add` and `delete` with the exact value, not `set`. A
  certificate for both `example.com` and `*.example.com` needs two TXT records
  with the same name at the same time; `set` would replace the first one.
- `ZONE` must be the domain as it is configured in DirectAdmin. For names under
  that domain (`www.example.com`, `mail.example.com`) set `DA_ZONE`, e.g.
  `DA_ZONE=example.com certbot ...`. The record name is passed fully qualified,
  so `da_dns.py` turns it into `_acme-challenge.www` within the zone.
- If validation fails with "no TXT record found", increase
  `DA_PROPAGATION_SECONDS`.

### Requesting a certificate

Test against the Let's Encrypt staging server first:

```sh
sudo certbot certonly --dry-run \
  --manual --preferred-challenges dns \
  --manual-auth-hook /opt/directadmin-dns-tools/certbot-auth.sh \
  --manual-cleanup-hook /opt/directadmin-dns-tools/certbot-cleanup.sh \
  -d example.com -d '*.example.com'
```

If that succeeds, run the same command without `--dry-run`.

For subdomains of a DirectAdmin domain, pass the zone:

```sh
sudo DA_ZONE=example.com certbot certonly \
  --manual --preferred-challenges dns \
  --manual-auth-hook /opt/directadmin-dns-tools/certbot-auth.sh \
  --manual-cleanup-hook /opt/directadmin-dns-tools/certbot-cleanup.sh \
  -d www.example.com -d shop.example.com
```

Note that environment variables like `DA_ZONE` are *not* stored by certbot, so
for automatic renewals of such certificates use small wrapper scripts that set
the zone, e.g. `/usr/local/bin/certbot-auth-example.com`:

```sh
#!/bin/sh
DA_ZONE=example.com exec /opt/directadmin-dns-tools/certbot-auth.sh
```

and the same for `certbot-cleanup.sh`, and pass the wrappers as the hooks.

### Renewal

Certbot saves the hook paths in `/etc/letsencrypt/renewal/<name>.conf`, so the
normal `certbot renew` timer/cron job reuses them. Check with:

```sh
sudo certbot renew --dry-run
```

Certbot runs as root: make sure root can read `credentials.txt` and
`dns_token.txt`, and keep both at mode 600. Alternatively, pass the key via the
`DA_KEY` environment variable, or point to other files with `-c` / `-k`.

## `da_dns.py` reference

```sh
./da_dns.py -d example.com list                          # all records
./da_dns.py -d example.com list --type TXT --name _acme-challenge
./da_dns.py -d example.com add A test 192.0.2.1          # no-op if it already exists
./da_dns.py -d example.com add MX @ "10 mail.example.com."
./da_dns.py -d example.com set A test 192.0.2.2          # replace all A records for 'test'
./da_dns.py -d example.com delete TXT _acme-challenge "token"
./da_dns.py -d example.com delete A test -y              # all A records for 'test'
./da_dns.py -d example.com export > example.com.zone.txt
./da_dns.py -d example.com ttl 600                       # or "default"
```

Names can be relative (`www`), `@` for the apex, or fully qualified with a
trailing dot (`www.example.com.`).

## `da_login_keys.py` reference

```sh
./da_login_keys.py list                    # shows allowed commands, expiry, use count
./da_login_keys.py create NAME --cmd CMD_API_DNS_CONTROL [--ip IP] [--expires "YYYY-MM-DD HH:MM"] [-o FILE]
./da_login_keys.py delete NAME
./da_login_keys.py test KEY_OR_FILE --domain example.com
```

Creating a key without `--cmd` gives it full access to the account; always
restrict keys used for automation.
