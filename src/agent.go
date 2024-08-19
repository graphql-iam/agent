package main

import (
	"github.com/graphql-iam/agent/src/cache"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/modules"
	"go.uber.org/fx"
)

const ConfigPathEnvName = "AGENT_CONFIG_PATH"

func main() {
	fx.New(
		fx.Provide(config.NewConfig),
		fx.Provide(cache.NewCache),
		modules.Repository,
		modules.Service,
		modules.Handler,
		modules.Server,
	).Run()
}
