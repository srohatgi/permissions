package test

import (
	"encoding/json"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/srohatgi/permissions/internal/authz"
)

func loadPolicySet(t *testing.T) *cedar.PolicySet {
	t.Helper()
	ps, err := cedar.NewPolicySetFromBytes("policies.cedar", []byte(authz.PolicySrc))
	if err != nil {
		var p cedar.Policy
		if err2 := p.UnmarshalCedar([]byte(authz.PolicySrc)); err2 != nil {
			t.Fatalf("parse policies: %v (fallback: %v)", err, err2)
		}
		tmp := cedar.NewPolicySet()
		tmp.Add("policy0", &p)
		ps = tmp
	}
	return ps
}

func setUpEntities(t *testing.T) cedar.EntityMap {
	t.Helper()
	entitiesJSON := `[
      {
        "uid": { "type": "Access::User", "id": "user:alice-app" },
        "attrs": {
          "tenantId": "T1",
          "permission": "urn:bd:applications/Console",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S3"]
          }
        },
        "parents": []
      },
      {
        "uid": { "type": "Access::User", "id": "user:bob" },
        "attrs": {
          "tenantId": "T1",
          "permission": "remove|dispensing|item",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S1"]
          }
        },
        "parents": []
      },
      {
        "uid": { "type": "Access::User", "id": "user:alice" },
        "attrs": {
          "tenantId": "T1",
          "permission": "remove|dispensing|item",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S3"]
          }
        },
        "parents": []
      },
      {
        "uid": { "type": "Access::Machine", "id": "machine:trent" },
        "attrs": {
          "tenantId": "T1",
          "permission": "remove|dispensing|item",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S3"]
          }
        },
        "parents": []
      },
      {
        "uid": { "type": "Access::Machine", "id": "machine:mallory" },
        "attrs": {
          "tenantId": "T1",
          "permission": "remove|dispensing|item",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S1"]
          }
        },
        "parents": []
      },
      {
        "uid": { "type": "Access::App", "id": "app:console" },
        "attrs": { "appUrn":"urn:bd:applications/Console", "tenantId":"T1" },
        "parents": []
      },
      {
        "uid": { "type": "Access::ApiEndpoint", "id": "ep:/dispense/remove" },
        "attrs": {
          "tenantId": "T1",
          "requiredPermission": "remove|dispensing|item",
          "constraints": {
            "Location_Facility": ["facility:T1"],
            "Dispensing_ItemSecurityCategory": ["S3"]
          }
        },
        "parents": []
      }
    ]`
	var entities cedar.EntityMap
	if err := json.Unmarshal([]byte(entitiesJSON), &entities); err != nil {
		t.Fatal(err)
	}
	return entities
}

func TestAppUse(t *testing.T) {
	ps := loadPolicySet(t)
	entities := setUpEntities(t)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice-app"),
		Action:    cedar.NewEntityUID("Access::Action", "app:use"),
		Resource:  cedar.NewEntityUID("Access::App", "app:console"),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision.String() != "allow" {
		t.Fatalf("expected allow, got %v", decision)
	}
}

func TestAPIInvokeAliceAllow(t *testing.T) {
	ps := loadPolicySet(t)
	entities := setUpEntities(t)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision.String() != "allow" {
		t.Fatalf("expected allow, got %v", decision)
	}
}

func TestAPIInvokeBobDeny(t *testing.T) {
	ps := loadPolicySet(t)
	entities := setUpEntities(t)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:bob"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision.String() != "deny" {
		t.Fatalf("expected deny, got %v", decision)
	}
}

func TestAPIInvokeTrentAllow(t *testing.T) {
	ps := loadPolicySet(t)
	entities := setUpEntities(t)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("Access::Machine", "machine:trent"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision.String() != "allow" {
		t.Fatalf("expected allow, got %v", decision)
	}
}

func TestAPIInvokeMalloryDeny(t *testing.T) {
	ps := loadPolicySet(t)
	entities := setUpEntities(t)
	req := cedar.Request{
		Principal: cedar.NewEntityUID("Access::Machine", "machine:mallory"),
		Action:    cedar.NewEntityUID("Access::Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/remove"),
	}
	decision, _ := cedar.Authorize(ps, entities, req)
	if decision.String() != "deny" {
		t.Fatalf("expected deny, got %v", decision)
	}
}
