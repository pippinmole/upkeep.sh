// Package migrations holds the Postgres schema migrations
// (golang-migrate's NNNN_name.up.sql / .down.sql) and runs them. The SQL is
// embedded in the binaries, so the upkeep-server image carries its own
// schema: cmd/migrate (/migrate in the image) applies it, and cmd/api and
// cmd/worker refuse to start against a database it has not been applied
// to (CheckSchema).
package migrations

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5" // registers the pgx5:// scheme
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

//go:embed *.sql
var files embed.FS

// FS returns the embedded migration files.
func FS() fs.FS { return files }

// table is golang-migrate's default version table, the one the migrate CLI
// used before the migrations were embedded, so existing databases carry on.
const table = "schema_migrations"

// Latest returns the highest migration version embedded in this binary.
func Latest() (uint, error) {
	src, err := iofs.New(files, ".")
	if err != nil {
		return 0, err
	}
	defer src.Close()
	v, err := src.First()
	if err != nil {
		return 0, err
	}
	for {
		next, err := src.Next(v)
		if errors.Is(err, os.ErrNotExist) {
			return v, nil
		}
		if err != nil {
			return 0, err
		}
		v = next
	}
}

// Migrator applies the embedded migrations to one database.
type Migrator struct {
	m *migrate.Migrate
}

// New connects to the database at dsn (a postgres:// or postgresql:// URL,
// as DATABASE_URL) and takes golang-migrate's driver over it. It fails if
// Postgres is unreachable; callers retry.
func New(dsn string) (*Migrator, error) {
	src, err := iofs.New(files, ".")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrateURL(dsn))
	if err != nil {
		_ = src.Close()
		return nil, err
	}
	return &Migrator{m: m}, nil
}

// migrateURL rewrites a Postgres URL to the pgx5:// scheme golang-migrate's
// pgx/v5 driver is registered under (it connects with postgres:// again).
func migrateURL(dsn string) string {
	for _, p := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(dsn, p) {
			return "pgx5://" + strings.TrimPrefix(dsn, p)
		}
	}
	return dsn
}

// Up applies every pending migration. An up-to-date database is not an
// error.
func (m *Migrator) Up() error {
	if err := m.m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return err
	}
	return nil
}

// Version returns the database's schema version and dirty flag (a failed
// migration left it half-applied). An empty database is version 0.
func (m *Migrator) Version() (version uint, dirty bool, err error) {
	version, dirty, err = m.m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}

// Close releases the source and the database connection.
func (m *Migrator) Close() error {
	srcErr, dbErr := m.m.Close()
	return errors.Join(srcErr, dbErr)
}

// Schema is a database's schema version against the binary's.
type Schema struct {
	Version uint // applied version; 0 when none
	Dirty   bool // a migration failed part-way
	Latest  uint // highest embedded version
}

// Ahead reports whether the database has migrations newer than this binary
// knows (e.g. after rolling back to an older image).
func (s Schema) Ahead() bool { return s.Version > s.Latest }

// Querier is the part of a pgx pool or connection CheckSchema needs.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// CheckSchema reads the database's schema version through db and returns
// an error naming the fix when the database is behind this binary or
// dirty. A database ahead of the binary is not an error; callers warn
// (Schema.Ahead). It never migrates.
func CheckSchema(ctx context.Context, db Querier) (Schema, error) {
	latest, err := Latest()
	if err != nil {
		return Schema{}, fmt.Errorf("read embedded migrations: %w", err)
	}
	s := Schema{Latest: latest}
	err = db.QueryRow(ctx, `SELECT version, dirty FROM `+table+` LIMIT 1`).Scan(&s.Version, &s.Dirty)
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Table created, nothing applied yet.
	case errors.As(err, &pgErr) && pgErr.Code == "42P01": // undefined_table
		// Never migrated.
	case err != nil:
		return s, fmt.Errorf("read schema version: %w", err)
	}
	const fix = "run the migrate service (/migrate in the upkeep-server image, with the same DATABASE_URL) and restart"
	switch {
	case s.Dirty:
		return s, fmt.Errorf("database schema is dirty: migration %d failed part-way; repair it by hand and clear the flag "+
			"(UPDATE %s SET dirty = false, with version set to the last migration fully applied), then %s", s.Version, table, fix)
	case s.Version == 0:
		return s, fmt.Errorf("database schema has no migrations applied (this build needs version %d): %s", s.Latest, fix)
	case s.Version < s.Latest:
		return s, fmt.Errorf("database schema is at version %d but this build needs %d: %s", s.Version, s.Latest, fix)
	}
	return s, nil
}
