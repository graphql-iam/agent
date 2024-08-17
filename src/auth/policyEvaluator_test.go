package auth

import (
	"github.com/graphql-iam/agent/src/model"
	"net/http/httptest"
	"testing"
)

func TestRolesResolver_Resolve_AllowAll(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	query := `
query {
  testData {
	data {
      name
	  title
	}
  }
}
`
	claims := map[string]interface{}{}

	pe := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     query,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "*",
						Effect:    "allow",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
		},
	}

	result := pe.EvaluateRoles([]model.Role{testRole})

	if !result {
		t.Fatal("Expected Result to be true")
	}
}

func TestRolesResolver_Resolve_DenyAll(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	query := `
query {
  testData {
	data {
      name
	  title
	}
  }
}
`
	claims := map[string]interface{}{}

	pe := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     query,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "*",
						Effect:    "deny",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
		},
	}

	result := pe.EvaluateRoles([]model.Role{testRole})

	if result {
		t.Fatal("Expected Result to be false")
	}
}

func TestRolesResolver_Resolve_AllowSpecific(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	queryDeny := `
query {
  testData {
	data {
      name
	  title
	}
  }
}
`

	queryAllow := `
query {
  testData {
	data {
      name
	}
  }
}
`

	claims := map[string]interface{}{}

	peDeny := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryDeny,
		Claims:    claims,
	}

	peAllow := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryAllow,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "query",
						Effect:    "allow",
						Resource:  "testData**",
						Condition: nil,
					},
				},
			},
			{
				ID:      "2",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "denyTitle",
						Action:    "query",
						Effect:    "deny",
						Resource:  "testData.data.title",
						Condition: nil,
					},
				},
			},
		},
	}

	result := peDeny.EvaluateRoles([]model.Role{testRole})

	if result {
		t.Fatalf("Expected Result to be false, query %s", queryDeny)
	}

	result = peAllow.EvaluateRoles([]model.Role{testRole})

	if !result {
		t.Fatalf("Expected Result to be true, query %s", queryAllow)
	}
}

func TestRolesResolver_Resolve_DenyMutation(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	queryDeny := `
mutation {
  testData {
	data {
      name
	}
  }
}
`

	queryAllow := `
query {
  testData {
	data {
      name
	}
  }
}
`

	claims := map[string]interface{}{}

	peDeny := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryDeny,
		Claims:    claims,
	}

	peAllow := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryAllow,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "query",
						Effect:    "allow",
						Resource:  "testData**",
						Condition: nil,
					},
				},
			},
			{
				ID:      "2",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "denyMutations",
						Action:    "mutation",
						Effect:    "deny",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
		},
	}

	result := peDeny.EvaluateRoles([]model.Role{testRole})

	if result {
		t.Fatalf("Expected Result to be false, query %s", queryDeny)
	}

	result = peAllow.EvaluateRoles([]model.Role{testRole})

	if !result {
		t.Fatalf("Expected Result to be true, query %s", queryAllow)
	}
}

func TestRolesResolver_Resolve_DenySpecificMutation(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	queryDeny := `
mutation {
  testData {
	data {
      name
      title
	}
  }
}
`

	queryAllow := `
mutation {
  testData {
	data {
      name
	}
  }
}
`

	claims := map[string]interface{}{}

	peDeny := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryDeny,
		Claims:    claims,
	}

	peAllow := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     queryAllow,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "mutation",
						Effect:    "allow",
						Resource:  "testData**",
						Condition: nil,
					},
				},
			},
			{
				ID:      "2",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "denyTitleMutation",
						Action:    "mutation",
						Effect:    "deny",
						Resource:  "testData.data.title",
						Condition: nil,
					},
				},
			},
		},
	}

	result := peDeny.EvaluateRoles([]model.Role{testRole})

	if result {
		t.Fatalf("Expected Result to be false, query %s", queryDeny)
	}

	result = peAllow.EvaluateRoles([]model.Role{testRole})

	if !result {
		t.Fatalf("Expected Result to be true, query %s", queryAllow)
	}
}

func TestRolesResolver_Resolve_WithCondition(t *testing.T) {
	requestAllow := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	requestAllow.Header.Set("X-Test", "some-allowed-value")
	requestDeny := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	requestDeny.Header.Set("X-Test", "test-val")
	variables := map[string]interface{}{}
	query := `
query {
  testData {
	data {
      name
	  title
	}
  }
}
`

	claims := map[string]interface{}{}

	peDeny := PolicyEvaluator{
		Request:   *requestDeny,
		Variables: variables,
		Query:     query,
		Claims:    claims,
	}

	peAllow := PolicyEvaluator{
		Request:   *requestAllow,
		Variables: variables,
		Query:     query,
		Claims:    claims,
	}

	testRole := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "query",
						Effect:    "allow",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
			{
				ID:      "2",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:      "denyTestHeader",
						Action:   "query",
						Effect:   "deny",
						Resource: "**",
						Condition: model.Condition{
							"StringEquals": model.ConditionParams{
								"header:X-Test": "test-val",
							},
						},
					},
				},
			},
		},
	}

	result := peDeny.EvaluateRoles([]model.Role{testRole})

	if result {
		t.Fatalf("Expected Result to be false, query %s", query)
	}

	result = peAllow.EvaluateRoles([]model.Role{testRole})

	if !result {
		t.Fatalf("Expected Result to be true, query %s", query)
	}
}

func TestRolesResolver_Resolve_MultipleRoles(t *testing.T) {
	request := httptest.NewRequest("POST", "http://testing.com/graphql", nil)
	variables := map[string]interface{}{}
	query := `
query {
  testData {
	data {
      name
	  title
	}
  }
}
`
	claims := map[string]interface{}{}

	pe := PolicyEvaluator{
		Request:   *request,
		Variables: variables,
		Query:     query,
		Claims:    claims,
	}

	testRole1 := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowAll",
						Action:    "*",
						Effect:    "allow",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
		},
	}

	testRole2 := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "denyAll",
						Action:    "*",
						Effect:    "deny",
						Resource:  "**",
						Condition: nil,
					},
				},
			},
		},
	}

	testRole3 := model.Role{
		Name: "test",
		Policies: []model.Policy{
			{
				ID:      "1",
				Name:    "test",
				Version: "1",
				Statements: []model.Statement{
					{
						Sid:       "allowSomeOther",
						Action:    "query",
						Effect:    "allow",
						Resource:  "some.other.path",
						Condition: nil,
					},
				},
			},
		},
	}

	// Two Allow
	result := pe.EvaluateRoles([]model.Role{testRole1, testRole1})

	if !result {
		t.Fatal("Expected Result to be true, two roles with allow")
	}

	// One Allow, one deny
	result = pe.EvaluateRoles([]model.Role{testRole1, testRole2})

	if !result {
		t.Fatal("Expected Result to be true, one role with allow and one with deny")
	}

	// two deny
	result = pe.EvaluateRoles([]model.Role{testRole2, testRole3})

	if result {
		t.Fatal("Expected Result to be false, two roles with deny")
	}
}
