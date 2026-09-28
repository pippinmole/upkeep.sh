package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pippinmole/upkeep.sh/server/internal/imagesbom"
	"github.com/pippinmole/upkeep.sh/server/internal/jobs"
	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// registryUserAgent identifies registry requests (image SBOM attestations).
const registryUserAgent = "upkeep.sh-worker/1 (container image SBOM fetch; +https://upkeep.sh)"

// imagesConfig reads the image_sbom settings from the environment.
func imagesConfig() jobs.ImagesConfig {
	return jobs.ImagesConfig{
		FetchEnabled:  envBool("SW_IMAGE_FETCH_ENABLED", true),
		Workers:       envInt("SW_IMAGE_JOB_WORKERS", jobs.DefaultImageWorkers),
		SweepInterval: envDuration("SW_IMAGE_SBOM_SWEEP_INTERVAL", jobs.DefaultImageSweepInterval),
		Registry: registry.Config{
			Guard:             netguard.FromEnv(),
			UserAgent:         registryUserAgent,
			DockerHubUsername: envOr("SW_DOCKERHUB_USERNAME", ""),
			DockerHubToken:    envOr("SW_DOCKERHUB_TOKEN", ""),
			MaxBlobBytes:      int64(envInt("SW_IMAGE_SBOM_MAX_BYTES", registry.DefaultMaxBlobBytes)),
			MaxManifestBytes:  int64(envInt("SW_IMAGE_MANIFEST_MAX_BYTES", registry.DefaultMaxManifestBytes)),
		},
	}
}

// runImageSBOM runs one image_sbom attempt in the foreground and prints
// its outcome. Matching of newly interned versions is left to the running
// worker's matcher_sweep (there is no River client here).
func runImageSBOM(ctx context.Context, db *store.Store, cfg jobs.ImagesConfig, args []string) error {
	if len(args) < 3 || len(args) > 4 {
		return fmt.Errorf("usage: worker image-sbom <image_id> <os> <arch> [variant]")
	}
	key := store.ImageKey{ImageID: args[0], OS: args[1], Arch: args[2]}
	if len(args) == 4 {
		key.Variant = args[3]
	}
	icfg := imagesbom.Config{Enabled: cfg.FetchEnabled}
	if cfg.FetchEnabled {
		icfg.Registry = registry.New(cfg.Registry)
	}
	out, err := (&imagesbom.Fetcher{Store: db, Cfg: icfg}).Run(ctx, key)
	if err != nil {
		return err
	}
	if out.Err != nil {
		fmt.Println("error:", out.Err)
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
	return nil
}
