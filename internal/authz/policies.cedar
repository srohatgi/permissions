// ===================== PERMITS =====================

// App access: principal must have a permission matching the app's URN
permit(principal, action == Access::Action::"app:use", resource)
when {
    principal.expandedPermissions.contains(resource.appUrn)
};


// API access: principal must have a permission matching the API endpoint's requiredPermission
permit(principal, action == Access::Action::"api:invoke", resource)
when {
    principal.expandedPermissions.contains(resource.requiredPermission) 
};


// ===================== FORBIDS =====================


// Deny when principal and resource tenants mismatch (if resource is tenant-scoped)
forbid(principal, action, resource)
when {
    (resource has tenantId)
    && ( !(principal has tenantId) || (principal has tenantId && principal.tenantId != resource.tenantId) )
};
