FROM quay.io/keycloak/keycloak:latest as builder

# Enable health and metrics support
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true
ARG KEYCLOAK_CERT_KEY
ARG KEYCLOAK_CERT
ARG KEYCLOAK_ADMIN
# Configure a database vendor
# ENV KC_DB=postgres

WORKDIR /opt/keycloak
RUN mkdir /opt/keycloak/certs
RUN touch /opt/keycloak/certs/tls.crt.pem
RUN echo "${KEYCLOAK_CERT}" >> /opt/keycloak/certs/tls.crt.pem
RUN touch /opt/keycloak/certs/tls.key.pem
RUN echo "${KEYCLOAK_CERT_KEY}" >> /opt/keycloak/certs/tls.key.pem

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:latest
COPY --from=builder /opt/keycloak/ /opt/keycloak/

# Allows adding a certificate to the key cloak trust store if we want it to verify other servers
# RUN keytool -importcert -storepass password -alias server -file ./opt/keycloak/certs/tls.crt.pem -keystore conf/server.keystore

# Copies to config file accross, may be overriden by the docker compose file volumes
# COPY ./backend/services/key-cloak/config/dev-config.json /opt/keycloak/data/import/dev-config.json

