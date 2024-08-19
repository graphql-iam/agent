package server

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/handler"
	"go.uber.org/fx"
	"net"
	"net/http"
)

func NewServer(lc fx.Lifecycle, policyProxy handler.PolicyProxy, healthHandler handler.HealthHandler, cfg config.Config) *http.Server {
	r := gin.Default()
	r.POST(cfg.Path, policyProxy.Handler)
	r.GET("/ping", healthHandler.Ping)
	srv := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", cfg.Port),
		Handler: r.Handler(),
	}

	lc.Append(fx.Hook{
		OnStart: func(ctx context.Context) error {
			ln, err := net.Listen("tcp", srv.Addr)
			if err != nil {
				return err
			}
			fmt.Println("Starting HTTP server at", srv.Addr)
			go srv.Serve(ln)
			return nil
		},
		OnStop: func(ctx context.Context) error {
			return srv.Shutdown(ctx)
		},
	})
	return srv
}
