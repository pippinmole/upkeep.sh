# Auth: self-hosted Auth.js, not a managed vendor (Clerk/Auth0)

Fits the project's self-hosted, no-vendor-sprawl pitch — a security
monitoring tool that itself depends on a third-party auth vendor is a
harder sell. Cost: we own session/password security (bcrypt cost 12,
`AUTH_SECRET`-signed JWT sessions), rather than offloading it.
