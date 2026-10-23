#!/bin/sh
# certbot --manual-cleanup-hook: remove the ACME challenge TXT record.
DIR=$(dirname "$(readlink -f "$0")")
ZONE="${DA_ZONE:-$CERTBOT_DOMAIN}"

"$DIR/da_dns.py" -d "$ZONE" delete TXT "_acme-challenge.$CERTBOT_DOMAIN." "$CERTBOT_VALIDATION"
