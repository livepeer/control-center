package secretservice

import (
	"context"
	"embed"
	"io/fs"

	"github.com/livepeer/control-center/api/internal/migrations"
)

//go:embed migrations/*.sql
var MigrationFiles embed.FS

var Migrator = migrations.ForSchema("lpsecrets")

func (s *Service) Migrate(ctx context.Context) error {
	files, err := fs.Sub(MigrationFiles, "migrations")
	if err != nil {
		return err
	}
	return Migrator.Up(ctx, s.DB, files)
}
