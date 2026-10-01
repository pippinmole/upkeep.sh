# upkeep.sh

## Tooling and git hooks

Dev tools are pinned in `mise.toml` (Go, golangci-lint, hk, rumdl, yamlfmt, hadolint, zizmor).
One-time setup per machine: `brew install mise`, then `mise trust && mise install` in the repo. Installing also runs
`hk install --mise`, which writes the git hooks (shared by every worktree).

- **pre-commit** (`hk.pkl`) fixes staged files: whitespace, newlines, YAML, Markdown, Dockerfiles, workflows,
  `go mod tidy` and `golangci-lint --fix` (per module: `server/`, `agent/`). If it rewrites files, review them,
  re-stage, and commit again.
- **commit-msg** enforces [Conventional Commits](https://www.conventionalcommits.org/):
  `type(scope): summary`, e.g. `fix(server): …`, `feat(agent): …`, `chore: …`. Use the area (`server`, `agent`,
  `web`, `docs`) as the scope.
- Never bypass the hooks with `--no-verify`.
- Before opening a PR run `hk check --all`.

## Lint rules

`.golangci.yml` is strict (gosec, revive, gocritic, errorlint, staticcheck, ...). Fix findings rather than
silencing them; a `//nolint` must name the linter and give a reason (`//nolint:gosec // why`), which
`nolintlint` enforces. Spelling is US English (misspell).

## CI

GitHub Actions is currently unavailable. Verify locally: `go vet ./...` and `go test ./...` in `server/` and
`agent/` (integration tests: `-tags integration` with `SW_TEST_DATABASE_URL` pointing at a migrated, throwaway
database), plus the web typecheck, lint, test and build.
