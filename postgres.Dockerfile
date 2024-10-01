FROM postgres:16

RUN apt-get update && apt-get upgrade
COPY --chmod=777 init.sql /docker-entrypoint-initdb.d 
# COPY --chmod=777 postrgres-init.sh /docker-entrypoint-initdb.d/init-user-db.sh 
