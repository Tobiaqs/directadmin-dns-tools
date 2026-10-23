#!/bin/sh
# certbot --manual-auth-hook: publish the ACME challenge TXT record.
set -e
DIR=$(dirname "$(readlink -f "$0")")
ZONE="${DA_ZONE:-$CERTBOT_DOMAIN}"

"$DIR/da_dns.py" -d "$ZONE" add TXT "_acme-challenge.$CERTBOT_DOMAIN." "$CERTBOT_VALIDATION"

# Give the DNS servers time to pick up the change before Let's Encrypt checks.
sleep "${DA_PROPAGATION_SECONDS:-60}"
