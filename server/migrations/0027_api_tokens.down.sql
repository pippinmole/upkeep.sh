BEGIN;

ALTER TABLE mcp_calls DROP CONSTRAINT mcp_calls_api_token_id_fkey;
DROP TABLE api_tokens;

COMMIT;
