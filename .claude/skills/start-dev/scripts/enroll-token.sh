#!/usr/bin/env bash
# Mints a one-time enrollment token in the dev DB and prints it. Same INSERT
# the dashboard's "Register agent" button runs (web/src/app/dashboard/
# actions.ts issueEnrollmentToken()), not a bypass.
#
# Hosts belong to the install's workspace (migrations/0023_members: the
# oldest row, as web/src/lib/viewer.ts getWorkspaceId() picks it); the
# user is only recorded as the token's issuer (created_by, then the
# agent's enrolled_by). That user is SW_TEST_USER_EMAIL if set; otherwise
# the only user, if there is exactly one. With several users and no email
# it fails and lists them rather than guessing.
#
# Usage: enroll-token.sh [agent name]   (run by test-agent-*.sh; prints the token)
set -euo pipefail

PSQL=(docker exec -i upkeep-sh-dev-postgres-1 psql -U swuser -d security_whatnot -Atq)

if [ -n "${SW_TEST_USER_EMAIL:-}" ]; then
  # Via stdin: psql only interpolates :'email' in script input, not -c.
  USER_ID="$(echo "SELECT id FROM users WHERE email = lower(:'email')" |
    "${PSQL[@]}" -v email="$SW_TEST_USER_EMAIL")"
  if [ -z "$USER_ID" ]; then
    echo "No user with email $SW_TEST_USER_EMAIL. Users:" >&2
    "${PSQL[@]}" -c "SELECT '  ' || email FROM users ORDER BY created_at" >&2
    exit 1
  fi
else
  COUNT="$("${PSQL[@]}" -c "SELECT count(*) FROM users")"
  if [ "$COUNT" != "1" ]; then
    echo "The dev DB has $COUNT users; set SW_TEST_USER_EMAIL to the account you sign in with:" >&2
    "${PSQL[@]}" -c "SELECT '  ' || email FROM users ORDER BY created_at" >&2
    exit 1
  fi
  USER_ID="$("${PSQL[@]}" -c "SELECT id FROM users")"
fi

TOKEN="$(node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))")"
echo "INSERT INTO enrollment_tokens (token, workspace_id, created_by, expires_at, agent_name)
  SELECT :'token', w.id, :'user', now() + interval '1 hour', nullif(:'name', '')
  FROM workspaces w ORDER BY w.created_at, w.id LIMIT 1" |
  "${PSQL[@]}" -v ON_ERROR_STOP=1 -v token="$TOKEN" -v user="$USER_ID" -v name="${1:-}" >/dev/null
echo "$TOKEN"
