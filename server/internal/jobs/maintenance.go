package jobs

import (
	"context"
	"log"
	"time"

	"github.com/riverqueue/river"

	"github.com/pippinmole/upkeep.sh/server/internal/store"
)

// QueueMaintenance: small periodic housekeeping (credential_cleanup).
const QueueMaintenance = "maintenance"

// DefaultCleanupInterval is the credential_cleanup cadence.
const DefaultCleanupInterval = time.Hour

// CredentialCleanupArgs deletes expired enrollment tokens and clears
// expired post-rotation previous secrets (store.CleanupCredentials).
type CredentialCleanupArgs struct{}

func (CredentialCleanupArgs) Kind() string { return "credential_cleanup" }
func (CredentialCleanupArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{Queue: QueueMaintenance, MaxAttempts: 3, UniqueOpts: uniqueWhileActive}
}

type CredentialCleanupWorker struct {
	river.WorkerDefaults[CredentialCleanupArgs]
	Store *store.Store
}

func (w *CredentialCleanupWorker) Timeout(*river.Job[CredentialCleanupArgs]) time.Duration {
	return 5 * time.Minute
}

func (w *CredentialCleanupWorker) Work(ctx context.Context, _ *river.Job[CredentialCleanupArgs]) error {
	r, err := w.Store.CleanupCredentials(ctx)
	if err != nil {
		return err
	}
	if r.EnrollmentTokens+r.PreviousSecrets > 0 {
		log.Printf("credential cleanup: %d expired enrollment tokens deleted, %d expired previous secrets cleared",
			r.EnrollmentTokens, r.PreviousSecrets)
	}
	return nil
}

// maintenanceJobs is the housekeeping schedule. It needs no network, so
// it runs regardless of Config.PeriodicSyncs.
func maintenanceJobs(cfg Config) []*river.PeriodicJob {
	if cfg.DisableMaintenanceSchedule {
		return nil
	}
	every := cfg.CleanupInterval
	if every <= 0 {
		every = DefaultCleanupInterval
	}
	return []*river.PeriodicJob{
		river.NewPeriodicJob(river.PeriodicInterval(every),
			func() (river.JobArgs, *river.InsertOpts) { return CredentialCleanupArgs{}, nil },
			&river.PeriodicJobOpts{ID: "credential_cleanup", RunOnStart: true}),
	}
}
