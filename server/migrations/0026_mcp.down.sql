BEGIN;

DROP TABLE mcp_calls;
DROP TABLE oauth_client_assertions;
DROP TABLE oauth_consents;
DROP TABLE oauth_access_tokens;
DROP TABLE oauth_refresh_tokens;
DROP TABLE oauth_client_resources;
DROP TABLE oauth_resources;
DROP TABLE oauth_clients;
DROP TABLE jwks;

COMMIT;
