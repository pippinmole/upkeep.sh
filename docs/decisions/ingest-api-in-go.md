# Ingest API in Go, not Next.js API routes

The agent protocol needs strict schema versioning and a per-agent bearer
credential, and shares its wire shape with the agent binary itself.
Ingestion, vuln matching, KEV/EPSS enrichment, and exposure analysis are
background, long-running/CPU-bound jobs — a persistent Go process with
real workers fits better than serverless-shaped Next.js route handlers.
