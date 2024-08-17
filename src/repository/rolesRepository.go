package repository

import (
	"encoding/json"
	"github.com/graphql-iam/agent/src/config"
	"github.com/graphql-iam/agent/src/model"
	"github.com/graphql-iam/agent/src/util"
	"github.com/patrickmn/go-cache"
	"net/http"
	"strings"
	"time"
)

type RolesRepository struct {
	Cfg   config.Config
	Cache *cache.Cache
}

func (r *RolesRepository) GetRoleByName(name string) (model.Role, error) {
	res, found := r.Cache.Get(name)
	if found {
		return res.(model.Role), nil
	}

	result, err := r.getRoleByNameFromManager(name)
	if err != nil {
		return model.Role{}, err
	}

	r.Cache.Set(name, result, cache.DefaultExpiration)
	return result, nil
}

func (r *RolesRepository) getRoleByNameFromManager(name string) (model.Role, error) {
	req, err := http.NewRequest("GET", r.Cfg.ManagerUrl+"/role", nil)
	if err != nil {
		return model.Role{}, err
	}
	q := req.URL.Query()
	q.Add("role", name)
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return model.Role{}, err
	}
	var role model.Role
	err = json.NewDecoder(res.Body).Decode(&role)
	if err != nil {
		return model.Role{}, err
	}
	return role, nil
}

func (r *RolesRepository) GetRolesByNames(names []string) ([]model.Role, error) {
	var cacheResult []model.Role
	unresolvedNames := names

	for _, name := range names {
		res, found := r.Cache.Get(name)
		if found {
			cacheResult = append(cacheResult, res.(model.Role))
			unresolvedNames = util.FilterArray(unresolvedNames, func(s string) bool {
				return s != name
			})
		}
	}
	if len(unresolvedNames) < 1 {
		return cacheResult, nil
	}

	queryResult, err := r.getRolesByNamesFromManager(names)
	if err != nil {
		return nil, err
	}

	for _, role := range queryResult {
		r.Cache.Set(role.Name, role, cache.DefaultExpiration)
	}

	return append(cacheResult, queryResult...), nil
}

func (r *RolesRepository) getRolesByNamesFromManager(names []string) ([]model.Role, error) {
	req, err := http.NewRequest("GET", r.Cfg.ManagerUrl+"/roles", nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("roles", strings.Join(names, ","))
	req.URL.RawQuery = q.Encode()

	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	var roles []model.Role
	err = json.NewDecoder(res.Body).Decode(&roles)
	if err != nil {
		return nil, err
	}
	return roles, nil
}
