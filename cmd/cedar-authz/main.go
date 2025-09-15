package main

import (
    _ "embed"
    "encoding/json"
    "fmt"
    "log"

    cedar "github.com/cedar-policy/cedar-go"
    "github.com/srohatgi/permissions/internal/authz"
)

// Policies are embedded in the internal/authz package for portability.

func main() {
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
        log.Printf("principal attrs: %s", e.Attributes.MarshalCedar())
    }
    if e, ok := entities.Get(cedar.NewEntityUID("Access::App", "app:console")); ok {
        log.Printf("resource attrs: %s", e.Attributes.MarshalCedar())
    }

    // Scenario A: app:use by Alice (permit)
    reqAppAlice := cedar.Request{
        Principal: cedar.NewEntityUID("Access::User", "user:alice"),
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

// buildEntities constructs sample entities matching the updated schema/policies.
func buildEntities() cedar.EntityMap {
    type uid struct{ Type, ID string }
    type entity struct {
        UID     uid                 `json:"uid"`
        Attrs   map[string]any      `json:"attrs"`
        Parents []map[string]string `json:"parents"`
    }
    // Build users Alice (permit) and Bob (deny), Console app, and a remove endpoint
    ents := []entity{
        {
            UID: uid{Type: "Access::User", ID: "user:alice"},
            Attrs: map[string]any{
                "tenantId": "T1",
                // convenience, derived from grants for policy without quantifiers
                "permSlugs": []any{"urn:bd:applications/Console", "remove:dispensing:item"},
                "itemSecurity": []any{"narcotic"},
                "facilities": []any{"FAC2"},
                // grants: Alice can use Console app and remove dispensing items with certain constraints
                "grants": []any{
                    map[string]any{
                        "bundles": []any{
                            // App access bundle: slug matches app slug
                            map[string]any{
                                "slug": "urn:bd:applications/Console",
                                "constraints": []any{},
                            },
                            // Functional access bundle: remove:dispensing:item with constraints
                            map[string]any{
                                "slug": "remove:dispensing:item",
                                "constraints": []any{
                                    map[string]any{
                                        "kind":   "urn:bd:dispensing:ItemSecurityCategory",
                                        "values": []any{"narcotic"}, // matches one of required values
                                    },
                                    map[string]any{
                                        "kind":   "urn:bd:Location/Facility",
                                        "values": []any{"FAC2"}, // matches one of required values
                                    },
                                },
                            },
                        },
                    },
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::User", ID: "user:bob"},
            Attrs: map[string]any{
                "tenantId": "T1",
                // convenience, derived from grants
                "permSlugs": []any{"remove:dispensing:item"},
                "itemSecurity": []any{"neuroblocker"},
                "facilities": []any{},
                // grants: Bob lacks the required app slug and/or functional bundle
                "grants": []any{
                    map[string]any{
                        "bundles": []any{
                            map[string]any{
                                "slug": "urn:bd:applications/Reports", // not Console
                                "constraints": []any{},
                            },
                            map[string]any{
                                "slug": "remove:dispensing:item",
                                // Missing one constraint kind, so API should deny
                                "constraints": []any{
                                    map[string]any{
                                        "kind":   "urn:bd:dispensing:ItemSecurityCategory",
                                        "values": []any{"neuroblocker"},
                                    },
                                    // Deliberately omit Location/Facility to force deny
                                },
                            },
                        },
                    },
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::Machine", ID: "machine:trent"},
            Attrs: map[string]any{
                "tenantId": "T1",
                "grants": []any{
                    map[string]any{
                        "bundles": []any{
                            map[string]any{
                                "slug": "remove:dispensing:item",
                                "constraints": []any{
                                    map[string]any{ "kind": "urn:bd:dispensing:ItemSecurityCategory", "values": []any{"neuroblocker"} },
                                    map[string]any{ "kind": "urn:bd:Location/Facility", "values": []any{"FAC3"} },
                                },
                            },
                        },
                    },
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::Machine", ID: "machine:mallory"},
            Attrs: map[string]any{
                "tenantId": "T1",
                "grants": []any{
                    map[string]any{
                        "bundles": []any{
                            map[string]any{
                                "slug": "remove:dispensing:item",
                                // Missing Facility constraint to force deny
                                "constraints": []any{
                                    map[string]any{ "kind": "urn:bd:dispensing:ItemSecurityCategory", "values": []any{"neuroblocker"} },
                                },
                            },
                        },
                    },
                },
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::App", ID: "app:console"},
            Attrs: map[string]any{"slug": "urn:bd:applications/Console", "tenantId": "T1"},
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::ApiEndpoint", ID: "ep:/dispense/remove"},
            Attrs: map[string]any{
                "tenantId": "T1",
                // The endpoint requires a Grant comprised of one Bundle 'remove:dispensing:item'
                // with ItemSecurityCategory any-of {neuroblocker, narcotic} AND Location/Facility any-of {FAC1,FAC2,FAC3}
                "required": map[string]any{
                    "bundles": []any{
                        map[string]any{
                            "slug": "remove:dispensing:item",
                            "constraints": []any{
                                map[string]any{
                                    "kind":   "urn:bd:dispensing:ItemSecurityCategory",
                                    "values": []any{"neuroblocker", "narcotic"},
                                },
                                map[string]any{
                                    "kind":   "urn:bd:Location/Facility",
                                    "values": []any{"FAC1", "FAC2", "FAC3"},
                                },
                            },
                        },
                    },
                },
            },
            Parents: []map[string]string{},
        },
    }
    // Marshal to JSON then into cedar.EntityMap
    b, _ := json.Marshal(ents)
    var entities cedar.EntityMap
    _ = json.Unmarshal(b, &entities)
    return entities
}

// buildEntitiesV2 constructs sample entities for the simplified schema:
// principals have `expandedPermissions` (Set<String>), apps use `appUrn`,
// and API endpoints use `requiredPermission`.
func buildEntitiesV2() cedar.EntityMap {
    type uid struct{ Type, ID string }
    type entity struct {
        UID     uid                 `json:"uid"`
        Attrs   map[string]any      `json:"attrs"`
        Parents []map[string]string `json:"parents"`
    }
    ents := []entity{
        {
            UID: uid{Type: "Access::User", ID: "user:alice"},
            Attrs: map[string]any{
                "tenantId":            "T1",
                "expandedPermissions": []any{"urn:bd:applications/Console", "remove|dispensing|item"},
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::User", ID: "user:bob"},
            Attrs: map[string]any{
                "tenantId":            "T1",
                "expandedPermissions": []any{"remove|inventory|item"},
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::Machine", ID: "machine:trent"},
            Attrs: map[string]any{
                "tenantId":            "T1",
                "expandedPermissions": []any{"remove|dispensing|item"},
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::Machine", ID: "machine:mallory"},
            Attrs: map[string]any{
                "tenantId":            "T1",
                "expandedPermissions": []any{"remove|dispensing|batch"},
            },
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::App", ID: "app:console"},
            Attrs: map[string]any{"appUrn": "urn:bd:applications/Console", "tenantId": "T1"},
            Parents: []map[string]string{},
        },
        {
            UID: uid{Type: "Access::ApiEndpoint", ID: "ep:/dispense/remove"},
            Attrs: map[string]any{
                "tenantId":           "T1",
                "requiredPermission": "remove|dispensing|item",
            },
            Parents: []map[string]string{},
        },
    }
    b, _ := json.Marshal(ents)
    var entities cedar.EntityMap
    _ = json.Unmarshal(b, &entities)
    return entities
}
