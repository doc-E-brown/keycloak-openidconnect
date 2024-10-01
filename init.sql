CREATE USER keycloak_user WITH PASSWORD 'password';
CREATE SCHEMA IF NOT EXISTS keycloak_schema AUTHORIZATION keycloak_user;
