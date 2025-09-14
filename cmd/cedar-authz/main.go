package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/srohatgi/permissions/internal/authz"
)

// Policies are embedded in the internal/authz package for portability.

func main() {
    // Flags to override ApiEndpoint requirements (defaults mirror current sample)
    epAnySlugsFlag := flag.String("ep-any-slugs", "dispense:item:opioid:write,dispense:item:*", "Comma-separated requiresAnySlugs for the ApiEndpoint")
    epAnyPairsFlag := flag.String("ep-any-constraint-pairs", "urn:bd:dispensing:ItemSecurityCategory#ScheduleII,urn:bd:dispensing:ItemSecurityCategory#ScheduleIII,urn:bd:Location/Facility#FAC-123", "Comma-separated requiresAnyConstraintPairs for the ApiEndpoint")
    flag.Parse()

    epAnySlugs := splitCSV(*epAnySlugsFlag)
    epAnyPairs := splitCSV(*epAnyPairsFlag)
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

    // Build entities programmatically so we can derive permConstraintPairs automatically
    entities := buildDefaultEntities(epAnySlugs, epAnyPairs)
    if e, ok := entities.Get(cedar.NewEntityUID("Access::User", "user:alice")); ok {
        log.Printf("principal attrs: %s", e.Attributes.MarshalCedar())
    }
    if e, ok := entities.Get(cedar.NewEntityUID("Access::App", "app:crm")); ok {
        log.Printf("resource attrs: %s", e.Attributes.MarshalCedar())
    }

	// Scenario A: app:use by user (T1)
	reqApp := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice"),
		Action:    cedar.NewEntityUID("Action", "app:use"),
		Resource:  cedar.NewEntityUID("Access::App", "app:crm"),
	}
    decision, diag := cedar.Authorize(ps, entities, reqApp)
    fmt.Println("app:use (alice):", decision, diag)

	// Scenario B: api:invoke where endpoint declares requirements
	reqAPI := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice"),
		Action:    cedar.NewEntityUID("Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/submit"),
	}
    decision, diag = cedar.Authorize(ps, entities, reqAPI)
    fmt.Println("api:invoke (alice, entity requires*):", decision, diag)

	// Scenario C: tenant mismatch forbid (machine has no tenant)
	reqAPIMachine := cedar.Request{
		Principal: cedar.NewEntityUID("Access::Machine", "machine:svc-reporter"),
		Action:    cedar.NewEntityUID("Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/submit"),
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPIMachine)
	fmt.Println("api:invoke (machine, tenant mismatch):", decision, diag)

	// Scenario D: api:invoke using context-driven requirements (ANY slugs + ANY constraints)
	ctx := cedar.NewRecord(cedar.RecordMap{
		"tenantId":                     cedar.String("T1"),
		"requiresAnySlugs":            cedar.NewSet(cedar.String("dispense:item:opioid:read")),
		"requiresAnyConstraintPairs":  cedar.NewSet(cedar.String("urn:bd:Location/Facility#FAC-123")),
	})
	reqAPIContext := cedar.Request{
		Principal: cedar.NewEntityUID("Access::User", "user:alice"),
		Action:    cedar.NewEntityUID("Action", "api:invoke"),
		Resource:  cedar.NewEntityUID("Access::ApiEndpoint", "ep:/dispense/submit"),
		Context:   ctx,
	}
	decision, diag = cedar.Authorize(ps, entities, reqAPIContext)
	fmt.Println("api:invoke (alice, context requires*):", decision, diag)
}

// splitCSV splits a comma-separated string into a slice of trimmed strings, ignoring empties.
func splitCSV(s string) []string {
    if s == "" { return nil }
    parts := strings.Split(s, ",")
    out := make([]string, 0, len(parts))
    for _, p := range parts {
        p = strings.TrimSpace(p)
        if p != "" { out = append(out, p) }
    }
    return out
}

// buildDefaultEntities constructs the sample entities and computes permConstraintPairs if missing.
func buildDefaultEntities(epAnySlugs, epAnyPairs []string) cedar.EntityMap {
    type uid struct{ Type, ID string }
    type entity struct {
        UID     uid                 `json:"uid"`
        Attrs   map[string]any      `json:"attrs"`
        Parents []map[string]string `json:"parents"`
    }
    // Defaults mirror previous inline JSON
    ents := []entity{
        {
            UID: uid{Type: "Access::User", ID: "user:alice"},
            Attrs: map[string]any{
                "tenantId": "T1",
                "permSlugs": []any{"app:urn:crm", "read:doc:123", "dispense:item:opioid:read"},
                "permConstraints": []any{
                    map[string]any{"kind": "urn:bd:Location/Facility", "values": []any{"FAC-123", "FAC-456"}},
                    map[string]any{"kind": "urn:bd:dispensing:ItemSecurityCategory", "values": []any{"ScheduleII", "HighRisk"}},
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::Machine", ID: "machine:svc-reporter"},
            Attrs: map[string]any{
                "permSlugs": []any{"app:urn:crm", "report:aggregate:*"},
                "permConstraints": []any{
                    map[string]any{"kind": "urn:bd:Location/Facility", "values": []any{"FAC-123"}},
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::App", ID: "app:crm"},
            Attrs: map[string]any{"slug": "app:urn:crm", "tenantId": "T1"},
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::ApiEndpoint", ID: "ep:/dispense/submit"},
            Attrs: map[string]any{
                "tenantId": "T1",
                "requiresAnySlugs": toAnySlice(epAnySlugs),
                "requiresAnyConstraintPairs": toAnySlice(epAnyPairs),
            },
            Parents: []map[string]string{},
        },
    }
    // Derive permConstraintPairs for principals if not present
    for i := range ents {
        ensureConstraintPairs(ents[i].Attrs)
    }
    // Marshal to JSON then into cedar.EntityMap
    b, _ := json.Marshal(ents)
    var entities cedar.EntityMap
    _ = json.Unmarshal(b, &entities)
    return entities
}

func toAnySlice(ss []string) []any {
    out := make([]any, len(ss))
    for i, s := range ss { out[i] = s }
    return out
}

// ensureConstraintPairs computes permConstraintPairs from permConstraints if missing.
func ensureConstraintPairs(attrs map[string]any) {
    if _, ok := attrs["permConstraintPairs"]; ok {
        return
    }
    pcRaw, ok := attrs["permConstraints"].([]any)
    if !ok { return }
    var pairs []string
    for _, item := range pcRaw {
        m, ok := item.(map[string]any)
        if !ok { continue }
        kind, _ := m["kind"].(string)
        vals, _ := m["values"].([]any)
        for _, v := range vals {
            if s, ok := v.(string); ok {
                pairs = append(pairs, kind+"#"+s)
            }
        }
    }
    if len(pairs) == 0 { return }
    attrs["permConstraintPairs"] = toAnySlice(pairs)
}
