package validate

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	cedarast "github.com/cedar-policy/cedar-go/ast"
	"github.com/cedar-policy/cedar-go/types"
	expast "github.com/cedar-policy/cedar-go/x/exp/ast"
	expschema "github.com/cedar-policy/cedar-go/x/exp/schema"
)

// Schema JSON mirrors (package-level to avoid function-scope forward-ref issues)
type jsonAttribute struct {
	Type       string                   `json:"type"`
	Required   bool                     `json:"required"`
	Element    *jsonType                `json:"element,omitempty"`
	Name       string                   `json:"name,omitempty"`
	Attributes map[string]jsonAttribute `json:"attributes,omitempty"`
}
type jsonType struct {
	Type       string                   `json:"type"`
	Element    *jsonType                `json:"element,omitempty"`
	Name       string                   `json:"name,omitempty"`
	Attributes map[string]jsonAttribute `json:"attributes,omitempty"`
}
type jsonEntity struct {
	Shape *jsonType `json:"shape,omitempty"`
}
type jsonAppliesTo struct {
	PrincipalTypes []string `json:"principalTypes"`
	ResourceTypes  []string `json:"resourceTypes"`
}
type jsonAction struct {
	AppliesTo jsonAppliesTo `json:"appliesTo"`
}
type jsonNamespace struct {
	EntityTypes map[string]jsonEntity `json:"entityTypes"`
	Actions     map[string]jsonAction `json:"actions"`
}

// ValidatePolicies parses the provided Cedar schema (human-readable .cedarschema)
// and Cedar policies (.cedar), then validates that:
//   - Each action referenced by a policy exists in the schema (same namespace).
//   - Attributes accessed on principal/resource exist on all appliesTo types
//     for that action.
//
// It returns an error describing all detected issues, or nil if validation passes.
func ValidatePolicies(schemaCedar, policiesCedar []byte) error {
	// Parse schema into JSON form so we can inspect it without importing internals.
	var s expschema.Schema
	s.SetFilename("schema.cedarschema")
	if err := s.UnmarshalCedar(schemaCedar); err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}
	schemaJSON, err := s.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal schema json: %w", err)
	}

	log.Printf("parsed schema: %s", schemaJSON)

	// Define minimal JSON schema structs (mirror of cedar-go internal schema JSON)
	type jsonAttribute struct {
		Type       string                   `json:"type"`
		Required   bool                     `json:"required"`
		Element    *jsonType                `json:"element,omitempty"`
		Name       string                   `json:"name,omitempty"`
		Attributes map[string]jsonAttribute `json:"attributes,omitempty"`
	}
	type jsonType struct {
		Type       string                   `json:"type"`
		Element    *jsonType                `json:"element,omitempty"`
		Name       string                   `json:"name,omitempty"`
		Attributes map[string]jsonAttribute `json:"attributes,omitempty"`
	}
	type jsonEntity struct {
		Shape *jsonType `json:"shape,omitempty"`
	}
	type jsonAppliesTo struct {
		PrincipalTypes []string `json:"principalTypes"`
		ResourceTypes  []string `json:"resourceTypes"`
	}
	type jsonAction struct {
		AppliesTo jsonAppliesTo `json:"appliesTo"`
	}
	type jsonNamespace struct {
		EntityTypes map[string]jsonEntity `json:"entityTypes"`
		Actions     map[string]jsonAction `json:"actions"`
	}
	var schema map[string]jsonNamespace
	if err := json.Unmarshal(schemaJSON, &schema); err != nil {
		return fmt.Errorf("unmarshal schema json: %w", err)
	}

	// Build attribute index: namespace -> entityType -> attribute names set
	type attrSet map[string]struct{}
	entityAttrs := make(map[string]map[string]attrSet) // ns -> type -> attrs
	for ns, nsDef := range schema {
		if entityAttrs[ns] == nil {
			entityAttrs[ns] = make(map[string]attrSet)
		}
		for et, ed := range nsDef.EntityTypes {
			attrs := make(attrSet)
			if ed.Shape != nil && ed.Shape.Type == "Record" {
				for name := range ed.Shape.Attributes {
					attrs[name] = struct{}{}
				}
			}
			entityAttrs[ns][et] = attrs
		}
	}

	// Parse policy list
	pl, err := cedar.NewPolicyListFromBytes("policies.cedar", policiesCedar)
	if err != nil {
		// Fallback to single policy parse for compatibility
		var p cedar.Policy
		if err2 := p.UnmarshalCedar(policiesCedar); err2 != nil {
			return fmt.Errorf("parse policies: %v (fallback: %v)", err, err2)
		}
		pl = cedar.PolicyList{&p}
	}

	var problems []string

	for _, pol := range pl {
		ast := pol.AST()

		// Determine namespace and action name from the Action scope
		ns, actionName, actionErr := extractAction(ast)
		if actionErr != nil {
			problems = append(problems, actionErr.Error())
			continue
		}
		if ns == "" || actionName == "" {
			// No explicit action constraint; skip schema-based validation for this policy
			continue
		}

		nsDef, ok := schema[ns]
		if !ok {
			problems = append(problems, fmt.Sprintf("policy references action in unknown namespace %q", ns))
			continue
		}
		act, ok := nsDef.Actions[actionName]
		if !ok {
			problems = append(problems, fmt.Sprintf("unknown action %q in namespace %q", actionName, ns))
			continue
		}

		// Collect attribute access on principal/resource in conditions
		usedPrincipalAttrs, usedResourceAttrs := collectConditionAttrs(ast)

		// Validate principal attributes exist for all principal types
		for attr := range usedPrincipalAttrs {
			for _, pt := range act.AppliesTo.PrincipalTypes {
				if _, ok := entityAttrs[ns][pt][attr]; !ok {
					problems = append(problems, fmt.Sprintf("action %q principal type %q missing attribute %q", actionName, pt, attr))
				}
			}
		}

		// Validate resource attributes exist for all resource types
		for attr := range usedResourceAttrs {
			for _, rt := range act.AppliesTo.ResourceTypes {
				if _, ok := entityAttrs[ns][rt][attr]; !ok {
					problems = append(problems, fmt.Sprintf("action %q resource type %q missing attribute %q", actionName, rt, attr))
				}
			}
		}
	}

	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func extractAction(p *cedarast.Policy) (namespace string, action string, err error) {
	switch a := p.Action.(type) {
	case expast.ScopeTypeEq:
		// Type is like "Namespace::Action"
		et := string(a.Entity.Type)
		parts := strings.Split(et, "::")
		if len(parts) == 0 {
			return "", "", fmt.Errorf("policy action has empty type")
		}
		ns := parts[0]
		return ns, string(a.Entity.ID), nil
	default:
		// Try to find an equality constraint on action in conditions.
		var foundNS, foundName string
		for _, c := range p.Conditions {
			if foundName != "" {
				break
			}
			walkNode(c.Body, func(n expast.IsNode) {
				eq, ok := n.(expast.NodeTypeEquals)
				if !ok || foundName != "" {
					return
				}
				// check action == EntityUID or reversed
				if v, ok := eq.Left.(expast.NodeTypeVariable); ok && string(v.Name) == "action" {
					if uid := tryEntityUID(eq.Right); uid != nil {
						parts := strings.Split(string(uid.Type), "::")
						if len(parts) > 0 {
							foundNS = parts[0]
							foundName = string(uid.ID)
						}
					}
				} else if v, ok := eq.Right.(expast.NodeTypeVariable); ok && string(v.Name) == "action" {
					if uid := tryEntityUID(eq.Left); uid != nil {
						parts := strings.Split(string(uid.Type), "::")
						if len(parts) > 0 {
							foundNS = parts[0]
							foundName = string(uid.ID)
						}
					}
				}
			})
		}
		if foundName == "" {
			// No explicit action constraint; skip validation for this policy
			return "", "", nil
		}
		return foundNS, foundName, nil
	}
}

func collectConditionAttrs(p *cedarast.Policy) (principalAttrs, resourceAttrs map[string]struct{}) {
	principalAttrs = make(map[string]struct{})
	resourceAttrs = make(map[string]struct{})
	for _, c := range p.Conditions {
		walkNode(c.Body, func(v expast.IsNode) {
			switch n := v.(type) {
			case expast.NodeTypeAccess:
				// attribute access: <Arg>.<Value>
				if name, ok := tryVariableName(n.StrOpNode.Arg); ok {
					switch string(name.Name) {
					case "principal":
						principalAttrs[string(n.Value)] = struct{}{}
					case "resource":
						resourceAttrs[string(n.Value)] = struct{}{}
					}
				}
			case expast.NodeTypeHas:
				if name, ok := tryVariableName(n.StrOpNode.Arg); ok {
					switch string(name.Name) {
					case "principal":
						principalAttrs[string(n.Value)] = struct{}{}
					case "resource":
						resourceAttrs[string(n.Value)] = struct{}{}
					}
				}
			}
		})
	}
	return principalAttrs, resourceAttrs
}

// tryVariableName returns the variable name if the node is a simple variable.
func tryVariableName(n expast.IsNode) (name expast.NodeTypeVariable, ok bool) {
	v, ok := n.(expast.NodeTypeVariable)
	return v, ok
}

// walkNode does a shallow AST traversal invoking fn for each visited node
func walkNode(n expast.IsNode, fn func(expast.IsNode)) {
	if n == nil {
		return
	}
	fn(n)
	switch v := n.(type) {
	case expast.NodeTypeOr:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeAnd:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeLessThan:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeLessThanOrEqual:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeGreaterThan:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeGreaterThanOrEqual:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeNotEquals:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeEquals:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeIn:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeHas:
		walkNode(v.Arg, fn)
	case expast.NodeTypeHasTag:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeLike:
		walkNode(v.Arg, fn)
	case expast.NodeTypeIs:
		walkNode(v.Left, fn)
	case expast.NodeTypeIsIn:
		walkNode(v.Left, fn)
		walkNode(v.Entity, fn)
	case expast.NodeTypeSub:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeAdd:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeMult:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeNegate:
		walkNode(v.Arg, fn)
	case expast.NodeTypeNot:
		walkNode(v.Arg, fn)
	case expast.NodeTypeAccess:
		walkNode(v.Arg, fn)
	case expast.NodeTypeGetTag:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeExtensionCall:
		for _, a := range v.Args {
			walkNode(a, fn)
		}
	case expast.NodeTypeContains:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeContainsAll:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeContainsAny:
		walkNode(v.Left, fn)
		walkNode(v.Right, fn)
	case expast.NodeTypeIsEmpty:
		walkNode(v.Arg, fn)
	case expast.NodeTypeRecord:
		for _, e := range v.Elements {
			walkNode(e.Value, fn)
		}
	case expast.NodeTypeSet:
		for _, e := range v.Elements {
			walkNode(e, fn)
		}
	case expast.NodeValue:
		// leaf
	case expast.NodeTypeVariable:
		// leaf
	default:
		// Unknown node type; ignore
	}
}

// tryEntityUID returns the EntityUID if the node is a value node containing one.
func tryEntityUID(n expast.IsNode) *types.EntityUID {
	if nv, ok := n.(expast.NodeValue); ok {
		if uid, ok := nv.Value.(types.EntityUID); ok {
			return &uid
		}
	}
	return nil
}
