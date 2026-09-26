# Self-hosted (Dokploy), not Vercel — this relies on next.config.ts's
# `output: "standalone"`, which traces only the deps actually used at
# runtime into .next/standalone, instead of shipping full node_modules.

FROM oven/bun:1.4.2-alpine AS deps
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

FROM oven/bun:1.4.2-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Build-time-only values; real secrets are injected at runtime below.
# DATABASE_URL/AUTH_SECRET aren't read during `next build` itself, but
# some libraries validate env at import time, so stub values keep the
# build hermetic and independent of production credentials.
ENV DATABASE_URL="postgres://build:build@localhost:5432/build"
ENV AUTH_SECRET="build-time-placeholder-not-used-at-runtime"
RUN bun run build

# Runtime stays on plain node: Next.js's standalone output's server.js is
# just a Node entrypoint, and node:24-alpine (current Active LTS) is
# smaller/more battle-tested for this than pulling bun in just to run it.
FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup --system --gid 1001 nodejs && adduser --system --uid 1001 nextjs

COPY --from=build /app/public ./public
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
