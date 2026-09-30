#!/usr/bin/env bash
# Mints a one-time enrollment token in the dev DB and prints it. Same INSERT
# the dashboard's "Register agent" button runs (web/src/app/dashboard/
# actions.ts createEnrollmentToken()), not a bypass.
#
# Whose account the test host lands in matters: the dashboard only shows a
# user their own hosts. The user is SW_TEST_USER_EMAIL if set; otherwise the
# only user, if there is exactly one. With several users and no email it
# fails and lists them rather than guessing (an earlier `LIMIT 1` enrolled
# hosts into a leftover test account, so they never showed up).
#
# Usage: enroll-token.sh   (run by test-agent-*.sh; prints the token)
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
"${PSQL[@]}" -c "INSERT INTO enrollment_tokens (token, user_id, expires_at) VALUES ('$TOKEN', '$USER_ID', now() + interval '1 hour');" >/dev/null
echo "$TOKEN"
