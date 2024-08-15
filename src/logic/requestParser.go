package logic

import (
	"errors"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
	"log"
)

func Parse(requestBody string) (map[string][]string, error) {
	fieldMap := make(map[string][]string)

	src := source.NewSource(&source.Source{
		Body: []byte(requestBody),
		Name: "GraphQL request",
	})

	queryAST, err := parser.Parse(parser.ParseParams{Source: src})

	if err != nil {
		log.Printf("failed to parse query: %v\n", err)
		return nil, errors.New("Failed to parse query " + requestBody)
	}

	for _, def := range queryAST.Definitions {
		if operation, ok := def.(*ast.OperationDefinition); ok {
			opType := operation.Operation
			fields := extractFields("", operation.SelectionSet.Selections)
			fieldMap[opType] = fields
		}
	}

	return fieldMap, nil
}

func extractFields(prefix string, selections []ast.Selection) []string {
	var fields []string
	for _, selection := range selections {
		switch sel := selection.(type) {
		case *ast.Field:
			qualifiedName := prefix + sel.Name.Value
			if sel.GetSelectionSet() != nil && len(sel.GetSelectionSet().Selections) > 0 {
				fields = append(fields, extractFields(qualifiedName+".", sel.SelectionSet.Selections)...)
			} else {
				fields = append(fields, qualifiedName)
			}
		case *ast.InlineFragment:
			fields = append(fields, extractFields(prefix, sel.SelectionSet.Selections)...)
		case *ast.FragmentSpread:
			fields = append(fields, prefix+sel.Name.Value)
		}
	}
	return fields
}
