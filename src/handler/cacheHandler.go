package handler

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"net/http"
)

type CacheHandler struct {
	Cache *cache.Cache
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
	c.Cache.Delete(body.Role)
	context.Status(http.StatusOK)
}

func (c *CacheHandler) Purge(context *gin.Context) {
	c.Cache.Flush()
	context.Status(http.StatusOK)
}
