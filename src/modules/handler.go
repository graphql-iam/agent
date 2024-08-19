package modules

import (
	"github.com/graphql-iam/agent/src/handler"
	"go.uber.org/fx"
)

var Handler = fx.Module("handler",
	fx.Provide(handler.NewPolicyProxy),
	fx.Provide(handler.NewHealthHandler),
	fx.Provide(handler.NewCacheHandler),
)
