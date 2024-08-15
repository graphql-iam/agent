package repository

import (
	"context"
	"errors"
	"fmt"
	"github.com/lars250698/graphql-iam/src/model"
	"github.com/lars250698/graphql-iam/src/util"
	"github.com/patrickmn/go-cache"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"time"
)

type RolesRepository struct {
	DB    *mongo.Database
	Cache *cache.Cache
}

func (r *RolesRepository) GetRoleByName(name string) (model.Role, error) {
	res, found := r.Cache.Get(name)
	if found {
		return res.(model.Role), nil
	}

	var result model.Role
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := r.DB.Collection("rolesWithPolicies").FindOne(ctx, bson.D{{"name", name}}).Decode(&result)
	if err != nil {
		fmt.Println(err.Error())
		return result, errors.New(fmt.Sprintf("could not find role with name %s", name))
	}

	r.Cache.Set(name, result, cache.DefaultExpiration)
	return result, nil
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

	var queryResult []model.Role
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := r.DB.Collection("rolesWithPolicies").Find(ctx, bson.D{{"name", bson.D{{"$in", unresolvedNames}}}})
	if err != nil {
		return nil, err
	}

	err = cur.All(ctx, &queryResult)
	if err != nil {
		return nil, err
	}

	for _, role := range queryResult {
		r.Cache.Set(role.Name, role, cache.DefaultExpiration)
	}

	return append(cacheResult, queryResult...), nil
}
