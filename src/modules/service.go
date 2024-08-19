package modules

import (
	"github.com/graphql-iam/agent/src/service"
	"go.uber.org/fx"
)

var Service = fx.Module("service",
	fx.Provide(service.NewAuthService),
	fx.Provide(service.NewJwtService),
)
