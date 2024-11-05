ACME_CHALLENGE_LABEL = "_acme-challenge"

# libdns doesn't require trailing slash
# https://github.com/libdns/acmedns/blob/c6aef518f41a8f2898c277a11e9b54106fa41006/provider.go#L112
API_ENDPOINT_BASE = "https://api.getlocalcert.net/api/v1/acme-dns-compat"

# Abuse limits
DOMAIN_PER_USER_LIMIT = 0 # Disable ahead of shutdown
DOMAIN_PER_STAFF_LIMIT = 1_000

# Disabled for shutdown
INSTANT_DOMAINS_PER_HOUR = 0
INSTANT_DOMAINS_PER_DAY_BURST = 0
INSTANT_DOMAINS_PER_WEEK = 0
DELEGATE_DOMAINS_PER_DAY = 0

# To match acme-dns (https://github.com/joohoi/acme-dns/issues/110#issuecomment-826147413)
TXT_RECORDS_PER_RRSET_LIMIT = 0 # Disabled for shutdown

# To match AWS AK/SK approach, keep two active to rotate keys
API_KEY_PER_ZONE_LIMIT = 0 # Disabled for shutdown

# Default Email Security Policy
#
# See: https://www.gov.uk/guidance/protect-domains-that-dont-send-email
# See: https://www.cloudflare.com/learning/dns/dns-records/protect-domains-without-email/
#
DEFAULT_SPF_POLICY = '"v=spf1 -all"'  # Reject all
DEFAULT_DMARC_POLICY = '"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"'  # reject, reject subdomain, strict dkim and spf
DEFAULT_DKIM_POLICY = '"v=DKIM1; p="'  # No signing keys
DEFAULT_MX_RECORD = "0 ."  # null route
