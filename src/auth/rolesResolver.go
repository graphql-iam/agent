package auth

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/lars250698/graphql-iam/src/config"
	"github.com/lars250698/graphql-iam/src/logic"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"strings"
)

type RolesResolver struct {
	Cfg    config.Config
	KeySet *jwk.Set
}

func (r *RolesResolver) Resolve(context *gin.Context) ([]string, error) {
	switch r.Cfg.Auth.Mode {
	case "jwt":
		return r.resolveRolesFromJwt(context)
	case "header":
		return r.resolveRolesFromHeader(context)
	}
	return nil, fmt.Errorf("mode %s is not a valid auth mode", r.Cfg.Auth.Mode)
}

func (r *RolesResolver) resolveRolesFromJwt(context *gin.Context) ([]string, error) {
	parser := logic.JwtParser{
		Cfg:    r.Cfg,
		KeySet: r.KeySet,
	}

	token, err := parser.Parse(context.GetHeader("Authorization"))
	if err != nil {
		return nil, err
	}

	rolesInterface, exists := token.Get(r.Cfg.Auth.JwtOptions.RoleClaim)
	if !exists {
		return nil, err
	}

	rolesString, ok := rolesInterface.(string)
	if !ok {
		return nil, err
	}

	return strings.Split(rolesString, ","), nil
}

func (r *RolesResolver) resolveRolesFromHeader(context *gin.Context) ([]string, error) {
	headerVal := context.GetHeader(r.Cfg.Auth.HeaderOptions.Name)
	if headerVal == "" {
		return nil, fmt.Errorf("header %s has no value", r.Cfg.Auth.HeaderOptions.Name)
	}
	return strings.Split(headerVal, ","), nil
}
