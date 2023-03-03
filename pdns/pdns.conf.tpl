# Postgres Backend
launch=gpgsql
gpgsql-host=db
gpgsql-port=5432
gpgsql-dbname={{ LOCALCERT_PDNS_DB_NAME }}
gpgsql-user={{ POSTGRES_USER }}
gpgsql-password={{ POSTGRES_PASSWORD }}

# not using primary/secondary setup
allow-unsigned-autoprimary=no

# No zone transfers (AXFR)
disable-axfr=yes
allow-unsigned-notify=no
# empty string to disable
allow-notify-from=

default-soa-content={{ LOCALCERT_PDNS_DEFAULT_SOA_CONTENT }}

# API
api=yes
api-key={{ LOCALCERT_SHARED_PDNS_API_KEY }}

webserver-address={{ LOCALCERT_PDNS_HOST }}
webserver-allow-from={{ LOCALCERT_PDNS_WEBSERVER_ALLOW_FROM }}

# Only the API, not the webserver
webserver=no
