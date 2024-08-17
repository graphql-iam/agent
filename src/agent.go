package main

import (
	"context"
	"fmt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/handler"
	"github.com/graphql-iam/agent/src/logic"
	"github.com/graphql-iam/agent/src/repository"
	"github.com/patrickmn/go-cache"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"time"
)

const ConfigPathEnvName = "AGENT_CONFIG_PATH"

func main() {
	configPath := "./config.yaml"

	if os.Getenv(ConfigPathEnvName) != "" {
		configPath = os.Getenv(ConfigPathEnvName)
	}

	cfg, err := config.GetConfig(configPath)
	if err != nil {
		panic(err)
	}

	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(cfg.MongoUrl))
	if err != nil {
		panic(err)
	}

	defer func() {
		if err = client.Disconnect(context.TODO()); err != nil {
			panic(err)
		}
	}()

	db := client.Database("graphql-iam")

	pipeline := mongo.Pipeline{
		{
			{"$lookup", bson.D{
				{"from", "policies"},
				{"localField", "policyIds"},
				{"foreignField", "id"},
				{"as", "policies"},
			}},
		},
		{
			{"$project", bson.D{
				{"name", 1},     // Assuming the role name is stored here
				{"policies", 1}, // The joined policies
				{"_id", 0},      // You can remove the original _id if you don't need it in the view
			}},
		},
	}

	err = db.CreateView(context.TODO(), "rolesWithPolicies", "roles", pipeline)
	if err != nil {
		log.Fatal(err)
	}

	expire := time.Duration(cfg.CacheOptions.Expiration) * time.Minute
	purge := time.Duration(cfg.CacheOptions.Purge) * time.Minute
	c := cache.New(expire, purge)

	rolesRepository := repository.RolesRepository{
		Cfg:   cfg,
		Cache: c,
	}

	policyProxy := handler.PolicyProxy{
		DB:              db,
		Cfg:             cfg,
		RolesRepository: &rolesRepository,
	}

	if cfg.Auth.JwtOptions.JwksUrl != "" {
		set := logic.NewJWKSet(cfg.Auth.JwtOptions.JwksUrl)
		policyProxy.KeySet = &set
	}

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: cfg.CorsOptions.AllowOrigins,
		AllowMethods: cfg.CorsOptions.AllowMethods,
		AllowHeaders: cfg.CorsOptions.AllowHeaders,
	}))
	r.POST(cfg.Path, policyProxy.Handler)
	r.GET("/ping", handler.Ping)

	err = r.Run(fmt.Sprintf("localhost:%d", cfg.Port))
	if err != nil {
		panic(err)
	}
}
