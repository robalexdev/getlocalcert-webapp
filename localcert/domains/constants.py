ACME_CHALLENGE_LABEL = "_acme-challenge"

# Abuse limits
DOMAIN_PER_USER_LIMIT = 5
DOMAIN_PER_STAFF_LIMIT = 1_000

INSTANT_DOMAINS_PER_HOUR = 100
INSTANT_DOMAINS_PER_DAY_BURST = 250
INSTANT_DOMAINS_PER_WEEK = 1000
DELEGATE_DOMAINS_PER_DAY = 1000

# To match acme-dns (https://github.com/joohoi/acme-dns/issues/110#issuecomment-826147413)
TXT_RECORDS_PER_RRSET_LIMIT = 2

# To match AWS AK/SK approach, keep two active to rotate keys
API_KEY_PER_ZONE_LIMIT = 2

# Default Email Security Policy
#
# See: https://www.gov.uk/guidance/protect-domains-that-dont-send-email
# See: https://www.cloudflare.com/learning/dns/dns-records/protect-domains-without-email/
#
DEFAULT_SPF_POLICY = '"v=spf1 -all"'  # Reject all
DEFAULT_DMARC_POLICY = '"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"'  # reject, reject subdomain, strict dkim and spf
DEFAULT_DKIM_POLICY = '"v=DKIM1; p="'  # No signing keys
DEFAULT_MX_RECORD = "0 ."  # null route
