package authz

import _ "embed"

//go:embed schema.cedarschema
var SchemaSrc string

//go:embed policies.cedar
var PolicySrc string

