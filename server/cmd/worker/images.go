package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/pippinmole/upkeep.sh/server/internal/imagesbom"
	"github.com/pippinmole/upkeep.sh/server/internal/imagescan"
	"github.com/pippinmole/upkeep.sh/server/internal/jobs"
	"github.com/pippinmole/upkeep.sh/server/internal/netguard"
	"github.com/pippinmole/upkeep.sh/server/internal/registry"
	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// registryUserAgent identifies registry requests (image SBOM attestations
// and image pulls).
const registryUserAgent = "upkeep.sh-worker/1 (container image SBOM fetch; +https://upkeep.sh)"

// imagesConfig reads the image_sbom / image_scan settings from the
// environment.
func imagesConfig() jobs.ImagesConfig {
	scan := imagescan.Config{
		Dir:                  envOr("SW_IMAGE_SCAN_DIR", ""),
		MaxCompressedBytes:   int64(envInt("SW_IMAGE_SCAN_MAX_COMPRESSED_BYTES", imagescan.DefaultMaxCompressedBytes)),
		MaxUncompressedBytes: int64(envInt("SW_IMAGE_SCAN_MAX_UNCOMPRESSED_BYTES", imagescan.DefaultMaxUncompressedBytes)),
		Timeout:              envDuration("SW_IMAGE_SCAN_TIMEOUT", imagescan.DefaultTimeout),
		CPUs:                 envInt("SW_IMAGE_SCAN_CPUS", imagescan.DefaultCPUs),
		MemoryBytes:          int64(envInt("SW_IMAGE_SCAN_MEMORY_BYTES", imagescan.DefaultMemoryBytes)),
	}
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
			// One layer may take the whole image's wall clock.
			LayerTimeout: scan.Timeout,
		},
		Scan:        envBool("SW_IMAGE_SCAN_ENABLED", true),
		Scanner:     scan,
		ScanWorkers: envInt("SW_IMAGE_SCAN_WORKERS", jobs.DefaultImageScanWorkers),
	}
}

// runImageSBOM runs one image_sbom attempt (scan: one image_scan attempt)
// in the foreground and prints its outcome. Matching of newly interned
// versions is left to the running worker's matcher_sweep (there is no
// River client here), and a hand-over to the scan isn't queued: run
// `worker image-scan` for that.
func runImageSBOM(ctx context.Context, db *store.Store, cfg jobs.ImagesConfig, scan bool, args []string) error {
	cmd := "image-sbom"
	if scan {
		cmd = "image-scan"
	}
	if len(args) < 3 || len(args) > 4 {
		return fmt.Errorf("usage: worker %s <image_id> <os> <arch> [variant]", cmd)
	}
	key := store.ImageKey{ImageID: args[0], OS: args[1], Arch: args[2]}
	if len(args) == 4 {
		key.Variant = args[3]
	}
	f := &imagesbom.Fetcher{Store: db, Cfg: jobs.ImagesFetcherConfig(cfg)}
	run := f.Run
	if scan {
		run = f.Scan
	}
	out, err := run(ctx, key)
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
