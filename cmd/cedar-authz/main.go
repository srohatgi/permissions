package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/srohatgi/permissions/internal/authz"
	"github.com/srohatgi/permissions/internal/authz/validate"
)

// Policies are embedded in the internal/authz package for portability.

func main() {
	// Validate embedded policy against embedded schema before running examples
	if err := validate.ValidatePolicies([]byte(authz.SchemaSrc), []byte(authz.PolicySrc)); err != nil {
		log.Fatalf("policy validation failed: %v", err)
	}

	// Parse policies list and add all to a PolicySet
	ps := cedar.NewPolicySet()
	if pl, err := cedar.NewPolicyListFromBytes("policies.cedar", []byte(authz.PolicySrc)); err == nil {
		for i, pol := range pl {
			ps.Add(cedar.PolicyID(fmt.Sprintf("p%03d", i)), pol)
		}
	} else {
		log.Printf("policy list parse error: %v", err)
		var p cedar.Policy
		if err2 := p.UnmarshalCedar([]byte(authz.PolicySrc)); err2 != nil {
			log.Fatalf("parse policies: %v (fallback: %v)", err, err2)
		}
		ps.Add("policy0", &p)
	}
	log.Printf("loaded %d policies", len(ps.Map()))

	// Build entities for the requested scenarios (simplified schema)
	entities := buildEntitiesV2()
	if e, ok := entities.Get(cedar.NewEntityUID("Access::User", "user:alice")); ok {
		log.Printf("principal attrs (api): %s", e.Attributes.MarshalCedar())
	}
	if e, ok := entities.Get(cedar.NewEntityUID("Access::User", "user:alice-app")); ok {
		log.Printf("principal attrs (app): %s", e.Attributes.MarshalCedar())
	}
	if e, ok := entities.Get(cedar.NewEntityUID("Access::App", "app:console")); ok {
		log.Printf("resource attrs: %s", e.Attributes.MarshalCedar())
	}

	// Scenario A: app:use by Alice (permit)
	reqAppAlice := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice-app"),
		Action:    cedar.NewEntityUID("Access::Action", "app:use"),
		Resource:  cedar.NewEntityUID("Access::App", "app:console"),
	}
	decision, diag := cedar.Authorize(ps, entities, reqAppAlice)
	fmt.Println("app:use (alice -> Console):", decision, diag)

	// Scenario B: app:use by Bob (deny)
	reqAppBob := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:bob"),
		Action:    cedar.NewEntityUID("Access::Action", "app:use"),
		Resource:  cedar.NewEntityUID("Access::App", "app:console"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAppBob)
	fmt.Println("app:use (bob -> Console):", decision, diag)

	// Scenario C: api:invoke by Alice (permit)
	reqAPIAlice := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPIAlice)
	fmt.Println("api:invoke (alice -> /dispense/remove):", decision, diag)

	// Scenario D: api:invoke by Bob (deny)
	reqAPIBob := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:bob"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPIBob)
	fmt.Println("api:invoke (bob -> /dispense/remove):", decision, diag)

	// Scenario E: api:invoke by Trent (machine) allowed
	reqAPITrent := cedar.Request{
		Principal: cedar.NewEntityUID("Access::Machine", "machine:trent"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPITrent)
	fmt.Println("api:invoke (trent -> /dispense/remove):", decision, diag)

	// Scenario F: api:invoke by Mallory (machine) denied
	reqAPIMallory := cedar.Request{
		Principal: cedar.NewEntityUID("Access::Machine", "machine:mallory"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPIMallory)
	fmt.Println("api:invoke (mallory -> /dispense/remove):", decision, diag)
}

// buildEntitiesV2 constructs sample entities for the simplified schema:
// principals expose `permission` and `constraints`, apps use `appUrn`,
// and API endpoints use `requiredPermission` with optional constraints.
func buildEntitiesV2() cedar.EntityMap {
	type uid struct{ Type, ID string }
	type entity struct {
		UID     uid                 `json:"uid"`
		Attrs   map[string]any      `json:"attrs"`
		Parents []map[string]string `json:"parents"`
	}
	ents := []entity{
		{
			UID: uid{Type: "Access::User", ID: "user:alice-app"},
			Attrs: map[string]any{
				"tenantId":   "T1",
				"permission": "urn:bd:applications/Console",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S3"},
				},
			},
			Parents: []map[string]string{},
		},
		{
			UID: uid{Type: "Access::User", ID: "user:alice"},
			Attrs: map[string]any{
				"tenantId":   "T1",
				"permission": "remove|dispensing|item",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S3"},
				},
			},
			Parents: []map[string]string{},
		},
		{
			UID: uid{Type: "Access::User", ID: "user:bob"},
			Attrs: map[string]any{
				"tenantId":   "T1",
				"permission": "remove|dispensing|item",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S1"},
				},
			},
			Parents: []map[string]string{},
		},
		{
			UID: uid{Type: "Access::Machine", ID: "machine:trent"},
			Attrs: map[string]any{
				"tenantId":   "T1",
				"permission": "remove|dispensing|item",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S3"},
				},
			},
			Parents: []map[string]string{},
		},
		{
			UID: uid{Type: "Access::Machine", ID: "machine:mallory"},
			Attrs: map[string]any{
				"tenantId":   "T1",
				"permission": "remove|dispensing|item",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S1"},
				},
			},
			Parents: []map[string]string{},
		},
		{
			UID:     uid{Type: "Access::App", ID: "app:console"},
			Attrs:   map[string]any{"appUrn": "urn:bd:applications/Console", "tenantId": "T1"},
			Parents: []map[string]string{},
		},
		{
			UID: uid{Type: "Access::ApiEndpoint", ID: "ep:/dispense/remove"},
			Attrs: map[string]any{
				"tenantId":           "T1",
				"requiredPermission": "remove|dispensing|item",
				"constraints": map[string]any{
					"Location_Facility":               []any{"facility:T1"},
					"Dispensing_ItemSecurityCategory": []any{"S3"},
				},
			},
			Parents: []map[string]string{},
		},
	}
	b, _ := json.Marshal(ents)
	var entities cedar.EntityMap
	_ = json.Unmarshal(b, &entities)
	return entities
}
