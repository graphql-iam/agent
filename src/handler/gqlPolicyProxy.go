package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/service"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type PolicyProxy struct {
	cfg         config.Config
	jwtService  *service.JwtService
	authService *service.AuthService
}

func NewPolicyProxy(cfg config.Config, jwtService *service.JwtService, authService *service.AuthService) PolicyProxy {
	return PolicyProxy{
		cfg:         cfg,
		jwtService:  jwtService,
		authService: authService,
	}
}

type policyProxyPostData struct {
	Query     string                 `json:"query"`
	Operation string                 `json:"operationName"`
	Variables map[string]interface{} `json:"variables"`
}

func (p *PolicyProxy) Handler(context *gin.Context) {
	jsonBytes, err := io.ReadAll(context.Request.Body)
	if err != nil {
		panic(err)
	}

	var data policyProxyPostData
	err = json.Unmarshal(jsonBytes, &data)
	if err != nil {
		fmt.Println(err.Error())
		context.AbortWithStatus(http.StatusBadRequest)
		return
	}

	rolesStr, err := p.resolveRoles(context)
	if err != nil {
		fmt.Printf("Error resolving roles: %v\n", err.Error())
		context.AbortWithStatus(http.StatusBadRequest)
		return
	}

	authorized, err := p.authService.AuthorizeWithRoles(rolesStr, *context.Request, data.Variables, data.Query)
	if err != nil {
		log.Printf("request was denied with error: %v\n", err)
		context.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !authorized {
		log.Println("Request was denied")
		context.AbortWithStatus(http.StatusBadRequest)
		return
	}

	p.proxyRequest(context, jsonBytes)
}

func (p *PolicyProxy) proxyRequest(context *gin.Context, data []byte) {
	proxyRequest, err := http.NewRequest("POST", p.cfg.SourceUrl, bytes.NewBuffer(data))
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create request"})
		return
	}

	for name, values := range context.Request.Header {
		for _, value := range values {
			proxyRequest.Header.Add(name, value)
		}
	}

	proxyRequest.Header.Add("X-Forwarded-For", context.ClientIP())
	proxyRequest.Header.Add("X-Forwarded-Proto", context.Request.Proto)

	proxyClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	proxyResponse, err := proxyClient.Do(proxyRequest)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to proxy request"})
		return
	}
	defer proxyResponse.Body.Close()

	proxyResponseBody, err := io.ReadAll(proxyResponse.Body)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read response"})
		return
	}

	context.Data(proxyResponse.StatusCode, proxyResponse.Header.Get("Content-Type"), proxyResponseBody)
}

func (p *PolicyProxy) resolveRoles(context *gin.Context) ([]string, error) {
	switch p.cfg.Auth.Mode {
	case "jwt":
		return p.resolveRolesFromJwt(context)
	case "header":
		return p.resolveRolesFromHeader(context)
	}
	return nil, fmt.Errorf("mode %s is not p valid auth mode", p.cfg.Auth.Mode)
}

func (p *PolicyProxy) resolveRolesFromJwt(context *gin.Context) ([]string, error) {
	token, err := p.jwtService.Parse(context.GetHeader("Authorization"))
	if err != nil {
		return nil, err
	}

	rolesInterface, exists := token.Get(p.cfg.Auth.JwtOptions.RoleClaim)
	if !exists {
		return nil, err
	}

	rolesString, ok := rolesInterface.(string)
	if !ok {
		return nil, err
	}

	return strings.Split(rolesString, ","), nil
}

func (p *PolicyProxy) resolveRolesFromHeader(context *gin.Context) ([]string, error) {
	headerVal := context.GetHeader(p.cfg.Auth.HeaderOptions.Name)
	if headerVal == "" {
		return nil, fmt.Errorf("header %s has no value", p.cfg.Auth.HeaderOptions.Name)
	}
	return strings.Split(headerVal, ","), nil
}
