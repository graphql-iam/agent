package handler

import (
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lars250698/graphql-iam/src/auth"
	"github.com/lars250698/graphql-iam/src/config"
	"github.com/lars250698/graphql-iam/src/repository"
	"go.mongodb.org/mongo-driver/mongo"
	"log"
	"time"
)

type PolicyEvaluator struct {
	DB  *mongo.Database
	Cfg config.Config
}

type policyEvaluatorPostData struct {
	Role      string                 `json:"role"`
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type policyEvaluatorResponse struct {
	Role   string `json:"role"`
	Result bool   `json:"result"`
}

func (pe *PolicyEvaluator) Handler(context *gin.Context) {
	start := time.Now()

	var p policyEvaluatorPostData
	err := json.NewDecoder(context.Request.Body).Decode(&p)
	if err != nil {
		context.AbortWithStatus(401)
		return
	}

	r := &repository.RolesRepository{DB: pe.DB}
	role, err := r.GetRoleByName(p.Role)
	if err != nil {
		fmt.Println(err.Error())
		context.AbortWithStatus(400)
		return
	}

	evaluator := auth.PolicyEvaluator{
		Request:   *context.Request,
		Variables: p.Variables,
		Query:     p.Query,
	}

	result := policyEvaluatorResponse{
		Role:   p.Role,
		Result: evaluator.EvaluateRole(role),
	}

	context.JSON(200, result)

	end := time.Now()
	executionTime := start.Unix() - end.Unix()
	log.Printf("Request executed in %dms\n", executionTime)

}
