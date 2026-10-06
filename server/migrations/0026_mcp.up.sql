-- MCP server (docs/MCP.md, docs/decisions/mcp-auth.md): the OAuth 2.1
-- authorization server tables for Better Auth's @better-auth/mcp plugin, the
-- jwt() plugin's signing keys, and the MCP call log.
--
-- The OAuth tables are the models of @better-auth/oauth-provider 1.7.7 (which
-- mcp() is built on) and of jwt(); @better-auth/cimd 1.7.7 adds no models of
-- its own (it stores CIMD clients in oauthClient). Columns and types follow
-- Better Auth's schema generator (the `auth` package, 1.7.7) for Postgres:
-- string[] and json fields are jsonb, dates timestamptz, ids uuid generated
-- by Postgres (advanced.database.generateId = "uuid", as in 0018), required
-- fields NOT NULL. Defaults the plugin fills in itself (booleans, created_at)
-- are repeated here only for rows written outside it.
--
-- web/src/lib/auth.ts maps every model and field onto these snake_case
-- names (each plugin's `schema` option); a field not listed below keeps its
-- name (e.g. oauthClient.name -> name):
--
--   jwt() jwks -> jwks
--     publicKey -> public_key, privateKey -> private_key,
--     createdAt -> created_at, expiresAt -> expires_at
--   oauthClient -> oauth_clients
--     clientId -> client_id, clientSecret -> client_secret,
--     clientDiscoveryId -> client_discovery_id, skipConsent -> skip_consent,
--     enableEndSession -> enable_end_session, subjectType -> subject_type,
--     clientCredentialsScopes -> client_credentials_scopes,
--     userId -> user_id, createdAt -> created_at, updatedAt -> updated_at,
--     softwareId -> software_id, softwareVersion -> software_version,
--     softwareStatement -> software_statement,
--     redirectUris -> redirect_uris,
--     postLogoutRedirectUris -> post_logout_redirect_uris,
--     backchannelLogoutUri -> backchannel_logout_uri,
--     backchannelLogoutSessionRequired -> backchannel_logout_session_required,
--     tokenEndpointAuthMethod -> token_endpoint_auth_method,
--     applicationType -> application_type, jwksUri -> jwks_uri,
--     grantTypes -> grant_types, responseTypes -> response_types,
--     requirePKCE -> require_pkce,
--     dpopBoundAccessTokens -> dpop_bound_access_tokens,
--     referenceId -> reference_id
--   oauthResource -> oauth_resources
--     accessTokenTtl -> access_token_ttl, refreshTokenTtl -> refresh_token_ttl,
--     signingAlgorithm -> signing_algorithm, signingKeyId -> signing_key_id,
--     allowedScopes -> allowed_scopes, customClaims -> custom_claims,
--     dpopBoundAccessTokensRequired -> dpop_bound_access_tokens_required,
--     createdAt -> created_at, updatedAt -> updated_at,
--     policyVersion -> policy_version
--   oauthClientResource -> oauth_client_resources
--     clientId -> client_id, resourceId -> resource_id, createdAt -> created_at
--   oauthRefreshToken -> oauth_refresh_tokens
--     clientId -> client_id, sessionId -> session_id, userId -> user_id,
--     referenceId -> reference_id, authorizationCodeId -> authorization_code_id,
--     requestedUserInfoClaims -> requested_user_info_claims,
--     expiresAt -> expires_at, createdAt -> created_at, rotatedAt -> rotated_at,
--     rotationReplayResponse -> rotation_replay_response,
--     rotationReplayExpiresAt -> rotation_replay_expires_at,
--     authTime -> auth_time
--   oauthAccessToken -> oauth_access_tokens
--     clientId -> client_id, sessionId -> session_id, userId -> user_id,
--     referenceId -> reference_id, authorizationCodeId -> authorization_code_id,
--     requestedUserInfoClaims -> requested_user_info_claims,
--     refreshId -> refresh_id, expiresAt -> expires_at, createdAt -> created_at
--   oauthConsent -> oauth_consents
--     clientId -> client_id, userId -> user_id, referenceId -> reference_id,
--     requestedUserInfoClaims -> requested_user_info_claims,
--     createdAt -> created_at, updatedAt -> updated_at
--   oauthClientAssertion -> oauth_client_assertions
--     expiresAt -> expires_at
--
-- Foreign keys are the generator's: a client, its tokens, consents and
-- resource links go with the user who owns them (ON DELETE CASCADE), tokens
-- with their client and refresh token; a signed-out session only clears
-- session_id on the tokens issued from it. Tokens and consents reference the
-- client by its public client_id (unique), not by id.
--
-- mcp_calls is ours (docs/MCP.md#activity-log): one row per tool call. It is
-- workspace data, so it outlives what it points at: removing a user or
-- revoking a client sets user_id / oauth_client_id to NULL rather than
-- deleting the history, like enrollment_tokens.created_by (0023).
--
-- Ownership: the OAuth tables and jwks are written only by Next.js (Better
-- Auth); mcp_calls is written by Next.js (/api/mcp) and pruned by the Go
-- worker (alert_prune, 90 days).

BEGIN;

-- Signing keys for the JWT access tokens (private_key is encrypted with
-- BETTER_AUTH_SECRET by the plugin).
CREATE TABLE jwks (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key  text NOT NULL,
    private_key text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz,
    alg         text,
    crv         text
);

-- OAuth clients. For a CIMD client client_id is its metadata document URL.
CREATE TABLE oauth_clients (
    id                                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                           text NOT NULL UNIQUE,
    client_secret                       text,
    client_discovery_id                 text,
    disabled                            boolean DEFAULT false,
    skip_consent                        boolean,
    enable_end_session                  boolean,
    subject_type                        text,
    scopes                              jsonb,
    client_credentials_scopes           jsonb DEFAULT '[]',
    user_id                             uuid REFERENCES users(id) ON DELETE CASCADE,
    created_at                          timestamptz DEFAULT now(),
    updated_at                          timestamptz DEFAULT now(),
    name                                text,
    uri                                 text,
    icon                                text,
    contacts                            jsonb,
    tos                                 text,
    policy                              text,
    software_id                         text,
    software_version                    text,
    software_statement                  text,
    redirect_uris                       jsonb NOT NULL,
    post_logout_redirect_uris           jsonb,
    backchannel_logout_uri              text,
    backchannel_logout_session_required boolean,
    token_endpoint_auth_method          text,
    application_type                    text,
    jwks                                text,
    jwks_uri                            text,
    grant_types                         jsonb,
    response_types                      jsonb,
    require_pkce                        boolean,
    dpop_bound_access_tokens            boolean DEFAULT false,
    reference_id                        text,
    metadata                            jsonb
);
CREATE INDEX oauth_clients_user_id_idx ON oauth_clients (user_id);

-- Protected resources (RFC 8707 audiences); mcp() registers /api/mcp.
CREATE TABLE oauth_resources (
    id                                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier                        text NOT NULL UNIQUE,
    name                              text NOT NULL,
    access_token_ttl                  integer,
    refresh_token_ttl                 integer,
    signing_algorithm                 text,
    signing_key_id                    text,
    allowed_scopes                    jsonb,
    custom_claims                     jsonb,
    dpop_bound_access_tokens_required boolean DEFAULT false,
    disabled                          boolean DEFAULT false,
    created_at                        timestamptz DEFAULT now(),
    updated_at                        timestamptz DEFAULT now(),
    policy_version                    integer DEFAULT 1,
    metadata                          jsonb
);

-- Which resources a client may request tokens for.
CREATE TABLE oauth_client_resources (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    resource_id text NOT NULL REFERENCES oauth_resources(identifier) ON DELETE CASCADE,
    metadata    jsonb,
    created_at  timestamptz DEFAULT now()
);
-- The model's unique (clientId, resourceId) index, under the name Better
-- Auth derives for it (it checks the index exists by that name).
CREATE UNIQUE INDEX oauth_client_resources_client_id_resource_id_uidx
    ON oauth_client_resources (client_id, resource_id);
CREATE INDEX oauth_client_resources_resource_id_idx ON oauth_client_resources (resource_id);

-- Refresh tokens (offline_access). token holds the plugin's hash of the
-- token, never the token itself.
CREATE TABLE oauth_refresh_tokens (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token                      text NOT NULL UNIQUE,
    client_id                  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    session_id                 uuid REFERENCES sessions(id) ON DELETE SET NULL,
    user_id                    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    reference_id               text,
    authorization_code_id      text,
    resources                  jsonb,
    requested_user_info_claims jsonb,
    expires_at                 timestamptz NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    revoked                    timestamptz,
    rotated_at                 timestamptz,
    rotation_replay_response   text,
    rotation_replay_expires_at timestamptz,
    auth_time                  timestamptz,
    confirmation               jsonb,
    scopes                     jsonb NOT NULL
);
CREATE INDEX oauth_refresh_tokens_client_id_idx ON oauth_refresh_tokens (client_id);
CREATE INDEX oauth_refresh_tokens_session_id_idx ON oauth_refresh_tokens (session_id);
CREATE INDEX oauth_refresh_tokens_user_id_idx ON oauth_refresh_tokens (user_id);
CREATE INDEX oauth_refresh_tokens_authorization_code_id_idx ON oauth_refresh_tokens (authorization_code_id);

-- Access tokens the plugin stores (opaque ones; JWT access tokens are
-- verified against jwks). token is hashed like the refresh token.
CREATE TABLE oauth_access_tokens (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token                      text NOT NULL UNIQUE,
    client_id                  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    session_id                 uuid REFERENCES sessions(id) ON DELETE SET NULL,
    user_id                    uuid REFERENCES users(id) ON DELETE CASCADE,
    reference_id               text,
    authorization_code_id      text,
    resources                  jsonb,
    requested_user_info_claims jsonb,
    refresh_id                 uuid REFERENCES oauth_refresh_tokens(id) ON DELETE CASCADE,
    expires_at                 timestamptz NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    revoked                    timestamptz,
    confirmation               jsonb,
    scopes                     jsonb NOT NULL
);
CREATE INDEX oauth_access_tokens_client_id_idx ON oauth_access_tokens (client_id);
CREATE INDEX oauth_access_tokens_session_id_idx ON oauth_access_tokens (session_id);
CREATE INDEX oauth_access_tokens_user_id_idx ON oauth_access_tokens (user_id);
CREATE INDEX oauth_access_tokens_authorization_code_id_idx ON oauth_access_tokens (authorization_code_id);
CREATE INDEX oauth_access_tokens_refresh_id_idx ON oauth_access_tokens (refresh_id);

-- A user's consent to a client's scopes (Settings -> Integrations ->
-- Connected apps lists and revokes these).
CREATE TABLE oauth_consents (
    id                         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id                    uuid REFERENCES users(id) ON DELETE CASCADE,
    reference_id               text,
    resources                  jsonb,
    requested_user_info_claims jsonb,
    scopes                     jsonb NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    updated_at                 timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_consents_client_id_idx ON oauth_consents (client_id);
CREATE INDEX oauth_consents_user_id_idx ON oauth_consents (user_id);

-- Used private_key_jwt client assertion ids (jti replay protection). The
-- plugin writes a hash of the jti as id, which isn't a uuid, so with
-- generateId = "uuid" Better Auth replaces it with a fresh one and the replay
-- check can't match; uuid is still the generator's type. Only confidential
-- clients authenticating with private_key_jwt use this; MCP clients (CIMD,
-- PKCE, token_endpoint_auth_method none) don't.
CREATE TABLE oauth_client_assertions (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    expires_at timestamptz NOT NULL
);

-- MCP call log (docs/MCP.md#activity-log). oauth_client_id is
-- oauth_clients.id (resolve it from the token's client_id when logging).
-- api_token_id has no foreign key yet: the API token table arrives with the
-- API tokens PR (docs/tasks/mcp-server.md, PR 9), which adds it.
CREATE TABLE mcp_calls (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    user_id         uuid REFERENCES users(id) ON DELETE SET NULL,
    credential_kind text NOT NULL CHECK (credential_kind IN ('oauth', 'api_token')),
    oauth_client_id uuid REFERENCES oauth_clients(id) ON DELETE SET NULL,
    api_token_id    uuid,
    client_name     text,
    tool            text NOT NULL,
    arguments       jsonb NOT NULL DEFAULT '{}',
    result_items    integer,
    duration_ms     integer NOT NULL,
    error           text,
    -- Only the credential kind's own reference may be set (either can turn
    -- NULL later, when the client or token is deleted).
    CONSTRAINT mcp_calls_credential_ref_check CHECK (
        (credential_kind = 'oauth' AND api_token_id IS NULL)
        OR (credential_kind = 'api_token' AND oauth_client_id IS NULL)
    )
);
CREATE INDEX mcp_calls_workspace_created_idx ON mcp_calls (workspace_id, created_at DESC);
CREATE INDEX mcp_calls_user_created_idx ON mcp_calls (user_id, created_at DESC);

COMMIT;
