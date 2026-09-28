# Next.js deploys as a Docker standalone image, not on Vercel

The whole pitch is self-hosting on your own VPS via Dokploy/Coolify.
`next.config.ts` sets `output: "standalone"` so the production image
only ships the traced runtime deps, not full `node_modules`
(`web/Dockerfile`, multi-stage: deps → build → runtime).
