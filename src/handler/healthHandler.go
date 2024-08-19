package handler

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

type HealthHandler struct{}

func NewHealthHandler() HealthHandler {
	return HealthHandler{}
}

func (h *HealthHandler) Ping(c *gin.Context) {
	c.Status(http.StatusOK)
}
