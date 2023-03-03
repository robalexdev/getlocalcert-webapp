# README

## Cheat Sheet

    $ docker compose build
    $ docker compose --env-file=dev.env up

    $ docker container ls
    $ docker logs <id>

## Fresh Start

For local testing it's nice to spin up a test environment.

First clear any old data:

    $ rm -Rf data/


Build everything:

    $ docker compose build


Start everything:

    $ docker compose --env-file=dev.env up

You'll see lots of errors as the database is not ready.


Open a shell in the database:

    $ docker exec -it --env-file=dev.env mvp-db-1 /bin/bash
    # env
    (observe the password)
    # psql -U ${POSTGRES_USER} -W
    (enter password)
    postgres=# CREATE DATABASE "localcert-web";
    postgres=# CREATE DATABASE "localcert-pdns";


Open a shell to the web server:

    $ docker exec -it --env-file=dev.env mvp-web-1 /bin/bash
    # python manage.py migrate


Create a fresh DNS server container (the normal one can't start without the tables):

    $ docker run -it --env-file=dev.env --net localcert-net mvp-pdns /bin/bash
    # psql -h db -U ${POSTGRES_USER} -d ${LOCALCERT_PDNS_DB_NAME} -a -f /usr/share/doc/pdns-backend-pgsql/schema.pgsql.sql
    Password:
    ...


Restart everything and it should now run.

## Django Testing

Clear old database, if needed:

    $ rm -Rf test-data/


Start local DNS and PG containers:

    $ docker compose -f docker-compose-test.yml build
    $ docker compose -f docker-compose-test.yml --env-file=test.env up


You should see the PDNS API online (it replies "Not Found"):

    $ curl 127.0.0.1:8081/
    Not Found


Setup testing env:

    $ source venv/bin/activate
    $ source test.env
    $ pip install -r requirements-dev.txt


Run tests:

    $ python manage.py test


Optionally run in parallel for a speedup:

    $ python manage.py test --parallel 12



## Important References

* PDNS API - https://doc.powerdns.com/authoritative/http-api/index.html
* acme-dns - https://github.com/joohoi/acme-dns/
