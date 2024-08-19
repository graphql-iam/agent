package modules

import (
	"github.com/graphql-iam/agent/src/repository"
	"go.uber.org/fx"
	"net/http"
	"time"
)

var Repository = fx.Module("repository",
	fx.Supply(http.Client{Timeout: 10 * time.Second}),
	fx.Provide(repository.NewRolesRepository),
)
