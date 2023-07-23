#!/bin/bash

set -e

cd ~/deploy/getlocalcert-webapp/
git pull

source prod.env

echo "Doing unsafe deploy then migrate (5 seconds)"
sleep 5

docker compose --env-file=prod.env build
docker compose --env-file=prod.env up -d
docker exec -it --env-file=prod.env getlocalcert-webapp-web-1 python manage.py migrate

