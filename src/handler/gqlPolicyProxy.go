package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lars250698/graphql-iam/src/auth"
	"github.com/lars250698/graphql-iam/src/config"
	"github.com/lars250698/graphql-iam/src/repository"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.mongodb.org/mongo-driver/mongo"
	"io"
	"log"
	"net/http"
	"time"
)

type PolicyProxy struct {
	DB              *mongo.Database
	Cfg             config.Config
	KeySet          *jwk.Set
	RolesRepository *repository.RolesRepository
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
		context.AbortWithStatus(400)
		return
	}

	rolesResolver := auth.RolesResolver{
		Cfg:    p.Cfg,
		KeySet: p.KeySet,
	}

	rolesStr, err := rolesResolver.Resolve(context)
	if err != nil {
		fmt.Println(err.Error())
		context.AbortWithStatus(401)
		return
	}
	roles, err := p.RolesRepository.GetRolesByNames(rolesStr)
	if err != nil {
		fmt.Println(err.Error())
		context.AbortWithStatus(401)
		return
	}

	pe := auth.PolicyEvaluator{
		Request:   *context.Request,
		Variables: data.Variables,
		Query:     data.Query,
	}
	if !pe.EvaluateRoles(roles) {
		log.Println("Request was denied")
		context.AbortWithStatus(401)
		return
	}

	p.proxyRequest(context, jsonBytes)
}

func (p *PolicyProxy) proxyRequest(context *gin.Context, data []byte) {
	proxyRequest, err := http.NewRequest("POST", p.Cfg.SourceUrl, bytes.NewBuffer(data))
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
