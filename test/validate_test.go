package test

import (
    "testing"

    "github.com/srohatgi/permissions/internal/authz"
    "github.com/srohatgi/permissions/internal/authz/validate"
)

func TestPoliciesValidate(t *testing.T) {
    if err := validate.ValidatePolicies([]byte(authz.SchemaSrc), []byte(authz.PolicySrc)); err != nil {
        t.Fatalf("validation failed: %v", err)
    }
}

