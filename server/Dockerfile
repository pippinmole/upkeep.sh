FROM golang:1.27.1-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Both binaries ship in one image: `api` (default entrypoint) and `worker`
# (compose overrides the entrypoint for the worker service).
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/api ./cmd/worker

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/api /api
COPY --from=build /out/worker /worker
ENTRYPOINT ["/api"]
