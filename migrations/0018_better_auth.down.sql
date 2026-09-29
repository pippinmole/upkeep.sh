BEGIN;

-- Restore users.password_hash from the credential accounts. A user with no
-- credential account (none today: password is the only sign-in method) gets
-- a value bcrypt never matches, so they cannot sign in until reset.
ALTER TABLE users ADD COLUMN password_hash text;
UPDATE users u
   SET password_hash = a.password
  FROM accounts a
 WHERE a.user_id = u.id AND a.provider_id = 'credential' AND a.password IS NOT NULL;
UPDATE users SET password_hash = '!' WHERE password_hash IS NULL;
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;

DROP TABLE verifications;
DROP TABLE accounts;
DROP TABLE sessions;

ALTER TABLE users
    DROP COLUMN name,
    DROP COLUMN email_verified,
    DROP COLUMN image,
    DROP COLUMN updated_at,
    DROP COLUMN username,
    DROP COLUMN display_username;

COMMIT;
