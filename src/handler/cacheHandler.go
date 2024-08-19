package handler

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"net/http"
)

type CacheHandler struct {
	cache *cache.Cache
}

func NewCacheHandler(cache *cache.Cache) *CacheHandler {
	return &CacheHandler{cache: cache}
}

type invalidateRequestBody struct {
	Role string `json:"role"`
}

// TODO Auth

func (c *CacheHandler) Invalidate(context *gin.Context) {
	var body invalidateRequestBody
	err := json.NewDecoder(context.Request.Body).Decode(&body)
	if err != nil {
		context.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.cache.Delete(body.Role)
	context.Status(http.StatusOK)
}

func (c *CacheHandler) Purge(context *gin.Context) {
	c.cache.Flush()
	context.Status(http.StatusOK)
}
