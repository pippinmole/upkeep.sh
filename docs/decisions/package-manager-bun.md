# Package manager: Bun (migrated from npm)

`web/` originally scaffolded with npm (`create-next-app --use-npm`),
migrated to Bun on request. `bun.lock` is the lockfile; Docker build/deps
stages use `oven/bun:1.4.2-alpine`, but the **runtime** stage stays on
plain `node:22`→`24-alpine` running `node server.js` — Next.js
standalone's entrypoint is plain Node, so there's no reason to ship Bun
into the runtime image just to run it.
