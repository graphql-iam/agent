package model

type policyEffect string

const (
	Allow policyEffect = "allow"
	Deny  policyEffect = "deny"
)

type Role struct {
	Name     string   `json:"name"`
	Policies []Policy `json:"policies"`
}

type Policy struct {
	ID         string      `json:"id,omitempty"`
	Name       string      `json:"name,omitempty"`
	Version    string      `json:"version"`
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Sid       string       `json:"sid,omitempty"`
	Action    string       `json:"action"`
	Effect    policyEffect `json:"effect"`
	Resource  string       `json:"resource"`
	Condition Condition    `json:"condition,omitempty"`
}

type Condition map[string]ConditionParams

type ConditionParams map[string]string
