package service

import (
	"fmt"
	"github.com/graphql-iam/agent/src/auth"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/repository"
	"net/http"
)

type AuthService struct {
	cfg             config.Config
	rolesRepository *repository.RolesRepository
}

func NewAuthService(cfg config.Config, rolesRepository *repository.RolesRepository) *AuthService {
	return &AuthService{
		cfg:             cfg,
		rolesRepository: rolesRepository,
	}
}

func (a *AuthService) AuthorizeWithRoles(rolesStr []string, request http.Request, Variables map[string]interface{}, query string) (bool, error) {
	roles, err := a.rolesRepository.GetRolesByNames(rolesStr)
	if err != nil {
		return false, fmt.Errorf("Error getting roles from manager: %v\n", err.Error())
	}

	pe := auth.PolicyEvaluator{
		Request:   request,
		Variables: Variables,
		Query:     query,
	}

	return pe.EvaluateRoles(roles), nil
}
