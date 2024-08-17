package auth

import (
	"fmt"
	"github.com/gobwas/glob"
	"github.com/graphql-iam/agent/src/logic"
	"github.com/graphql-iam/agent/src/model"
	"github.com/graphql-iam/agent/src/util"
	"net/http"
)

type PolicyEvaluator struct {
	Request   http.Request
	Variables map[string]interface{}
	Query     string
	Claims    map[string]interface{}
}

func (pe *PolicyEvaluator) EvaluateRoles(roles []model.Role) bool {
	anyMatch := false
	for _, role := range roles {
		if pe.evaluateRole(role) {
			anyMatch = true
			break
		}
	}
	return anyMatch
}

func (pe *PolicyEvaluator) evaluateRole(role model.Role) bool {
	for _, policy := range role.Policies {
		pass := pe.evaluatePolicy(policy)
		if !pass {
			return false
		}
	}
	return true
}

func (pe *PolicyEvaluator) evaluatePolicy(policy model.Policy) bool {
	actionResourceMap, err := logic.Parse(pe.Query)
	if err != nil {
		return false
	}

	for action, resources := range actionResourceMap {
		pass := pe.evaluateStatementsForAction(action, resources, policy.Statements)
		if !pass {
			return false
		}
	}
	return true
}

func (pe *PolicyEvaluator) evaluateStatementsForAction(action string, resources []string, statements []model.Statement) bool {
	statements = pe.statementsForAction(action, statements)
	return !pe.anyDenied(resources, statements) && pe.allAllowed(resources, statements)
}

func (pe *PolicyEvaluator) anyDenied(resources []string, statements []model.Statement) bool {
	statements = pe.denyStatements(statements)
	for _, statement := range statements {
		match := false

		for _, resource := range resources {
			g, err := glob.Compile(statement.Resource, '.')
			if err != nil {
				fmt.Printf("Resource %s is malformed\n", statement.Resource)
			}
			if g.Match(resource) {
				match = true
				break
			}
		}

		if statement.Condition != nil {
			evaluator := ConditionEvaluator{
				condition: statement.Condition,
				request:   pe.Request,
				variables: pe.Variables,
				query:     pe.Query,
				claims:    pe.Claims,
			}

			conditionMet := evaluator.Evaluate()
			match = match && conditionMet
		}

		if match {
			fmt.Printf("Request was explicitly denied by statement %s\n", statement)
			return true
		}
	}
	return false
}

func (pe *PolicyEvaluator) allAllowed(resources []string, statements []model.Statement) bool {
	statements = pe.allowStatements(statements)
	for _, statement := range statements {
		match := true

		for _, resource := range resources {
			g, err := glob.Compile(statement.Resource, '.')
			if err != nil {
				fmt.Printf("Resource %s is malformed\n", statement.Resource)
			}

			match = match && g.Match(resource)
		}

		if statement.Condition != nil {
			evaluator := ConditionEvaluator{
				condition: statement.Condition,
				request:   pe.Request,
				variables: pe.Variables,
				query:     pe.Query,
			}

			conditionMet := evaluator.Evaluate()

			match = match && conditionMet
		}

		if !match {
			return false
		}
	}
	return true
}

func (pe *PolicyEvaluator) statementsForAction(action string, statements []model.Statement) []model.Statement {
	return util.FilterArray(statements, func(statement model.Statement) bool {
		g, err := glob.Compile(statement.Action)
		if err != nil {
			fmt.Printf("Action %s is malformed\n", statement.Action)
			return false
		}
		return g.Match(action)
	})
}

func (pe *PolicyEvaluator) denyStatements(allStatements []model.Statement) []model.Statement {
	return util.FilterArray(allStatements, func(statement model.Statement) bool {
		return statement.Effect == model.Deny
	})
}

func (pe *PolicyEvaluator) allowStatements(allStatements []model.Statement) []model.Statement {
	return util.FilterArray(allStatements, func(statement model.Statement) bool {
		return statement.Effect == model.Allow
	})
}
