ACME_CHALLENGE_LABEL = "_acme-challenge"

# Abuse limit
DOMAIN_PER_USER_LIMIT = 3

# To match acme-dns (https://github.com/joohoi/acme-dns/issues/110#issuecomment-826147413)
TXT_RECORDS_PER_RRSET_LIMIT = 2

# To match AWS AK/SK approach, keep two active to rotate keys
API_KEY_PER_ZONE_LIMIT = 2
