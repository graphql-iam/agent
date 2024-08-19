package cache

import (
	"github.com/graphql-iam/agent/src/config"
	"github.com/patrickmn/go-cache"
	"time"
)

func NewCache(cfg config.Config) *cache.Cache {
	expire := time.Duration(cfg.CacheOptions.Expiration) * time.Minute
	purge := time.Duration(cfg.CacheOptions.Purge) * time.Minute
	return cache.New(expire, purge)
}
