// ===================== PERMITS =====================

// App access: principal must have a permission matching the app's URN
permit(principal, action == Access::Action::"app:use", resource is Access::App)
when {
    principal.permission == resource.appUrn
};


// API access: principal must have a permission matching the API endpoint's requiredPermission
permit(principal, action == Access::Action::"api:invoke", resource is Access::ApiEndpoint)
when {
  // Permission must match
  principal.permission == resource.requiredPermission

  // Tenant guard: if resource has a tenant, principal must have the same tenant
  && (
       !(resource has tenantId)
       || (
            resource has tenantId
            && principal has tenantId
             && principal.tenantId == resource.tenantId
          )
     )

  // If resource declares Location_Facility, principal must include all of them
  && (
       !(resource.constraints has Location_Facility)
       || (
            resource.constraints has Location_Facility
            && resource.constraints.Location_Facility.contains("*")
          )
       || (
            (principal.constraints has Location_Facility)
            && resource.constraints has Location_Facility
            && principal.constraints.Location_Facility.containsAll(resource.constraints.Location_Facility)
          )
     )

  // If resource declares Dispensing_ItemSecurityCategory, principal must include all of them
  && (
       !(resource.constraints has Dispensing_ItemSecurityCategory)
       || (
            resource.constraints has Dispensing_ItemSecurityCategory
            && resource.constraints.Dispensing_ItemSecurityCategory.contains("*")
        )
       || (
            (principal.constraints has Dispensing_ItemSecurityCategory)
            && resource.constraints has Dispensing_ItemSecurityCategory
            && principal.constraints.Dispensing_ItemSecurityCategory.containsAll(
                 resource.constraints.Dispensing_ItemSecurityCategory
               )
          )
     )
};


// ===================== FORBIDS =====================

// Deny when principal and resource tenants mismatch (if resource is tenant-scoped)
forbid(principal, action, resource)
when {
  (resource has tenantId)
  && (
       !(principal has tenantId)
       || (
        principal has tenantId
        && principal.tenantId != resource.tenantId
       )
     )
};
