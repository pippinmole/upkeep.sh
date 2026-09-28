# Test SMTP server (Mailpit)

A throwaway local SMTP server for testing the email notification channel: it
accepts mail with a fixed test login, delivers nothing, and shows every
message in a web UI.

## Start and stop

From the repo root:

```sh
docker compose -f dev/smtp/compose.yaml up -d     # start
docker compose -f dev/smtp/compose.yaml down      # stop (captured mail is discarded)
```

Or run `docker compose up -d` / `docker compose down` from inside `dev/smtp/`.

- SMTP: port **2525** on your machine
- Captured mail: **http://localhost:8025** (web UI; the API is at
  `http://localhost:8025/api/v1/messages`)

## Worker prerequisite

The worker delivers notifications, including "Send test", and its network
guard refuses private and loopback addresses. Mailpit is on your machine, so
the worker needs the dev-only escape hatch `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true`.
Port 2525 is already an allowed SMTP port, so the port isn't why it's needed.

With the dev stack (`docker-compose.dev.yml`), add this line to the repo-root
`.env`, which compose reads (or export it in your shell):

```sh
SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true
```

Then recreate the worker: `docker compose -f docker-compose.dev.yml up -d worker`.
Never set it in production.

## Channel settings

In the dashboard, open **Settings → Notification settings → Add channel → Email**
and enter:

| Field | Value |
|---|---|
| Name | `Local test SMTP` |
| To | `ops@example.com` |
| From address | `alerts@upkeep.sh` |
| SMTP server address | `host.docker.internal` (the worker runs in Docker in the dev stack); `localhost` if you run the worker natively |
| Port | `2525` |
| Security | **None** |
| Username | `alerts@upkeep.sh` |
| Password | `upkeep-test-password` |
| Allow insecure authentication | **On** |

Then click **Send test**. The message appears at http://localhost:8025.

Why Security None: the notifier always verifies TLS certificates and has no
"skip verification" option, so a self-signed certificate would be rejected. Without TLS,
the notifier only sends the username and password when "Allow insecure
authentication" is on.

`host.docker.internal` is how a Docker Desktop container reaches ports
published on your machine, so this works whichever stack you start first.

## Report emails

To see a scheduled report as an email: in **Settings → Notification
settings → Reports**, add a schedule that sends to this channel and click
**Send now**. The message appears at http://localhost:8025; Mailpit's
HTML and Text tabs show the two parts.

The worker has the HTML rendered by the Next.js dev server
(`http://host.docker.internal:3000`, see `docker-compose.dev.yml`), so
`bun run dev` must be running, and `web/.env.local` needs the
`SW_INTERNAL_RENDER_SECRET` and `SW_WEB_INTERNAL_URL` lines from
`web/.env.example` (the start-dev skill's `up.sh` adds them; restart
`bun run dev` after adding them by hand). Otherwise no report email
arrives and the delivery log shows the render error. To iterate on the template itself, `bun run email` in `web/`
previews it without sending anything.

## Troubleshooting

- **"... is a loopback/private address: destination not allowed"**: the worker
  doesn't have `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true`. Set it (see above)
  and recreate the worker container. The value only applies after the recreate.
- **Connection refused**: Mailpit isn't running (`docker compose -f
  dev/smtp/compose.yaml ps`), or the host is wrong. From the worker
  container, `localhost` is the container itself, so use `host.docker.internal`.
- **"authentication failed: SMTP 535 ... credentials invalid"**: the username
  or password doesn't match the table above (`MP_SMTP_AUTH` in `compose.yaml`).
- **"SMTP 530 ... Authentication required"**: the username and password
  are blank. This server requires them.
- **"security is None, so the password would be sent unencrypted"**: turn on
  "Allow insecure authentication".
- **STARTTLS/TLS errors**: set Security to None. This server has no TLS.
