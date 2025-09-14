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
        "uid": { "type": "Access::User", "id": "user:alice" },
        "attrs": { "tenantId":"T1", "permSlugs":["app:urn:crm"], "permConstraints": [] },
        "parents": []
      },
      {
        "uid": { "type": "Access::App", "id": "app:crm" },
        "attrs": { "slug":"app:urn:crm", "tenantId":"T1" },
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
        Principal: cedar.NewEntityUID("Access::User", "user:alice"),
        Action:    cedar.NewEntityUID("Action", "app:use"),
        Resource:  cedar.NewEntityUID("Access::App", "app:crm"),
    }
    decision, _ := cedar.Authorize(ps, entities, req)
    if decision.String() != "allow" {
        t.Fatalf("expected allow, got %v", decision)
    }
}
