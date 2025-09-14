// ============ APP ACCESS (Multi-Tenant) ============
permit(principal, action == Action::"app:use", resource)
when { principal.permSlugs.contains(resource.slug) };


// ============ APP ACCESS (Tenant-Scoped) ============
forbid(principal, action == Action::"app:use", resource)
when { (resource has tenantId) && ( !(principal has tenantId) || principal.tenantId != resource.tenantId ) };


// ============ API INVOKE (resource-declared in connected.yaml) ============
permit(principal, action == Action::"api:invoke", resource)
when {
    (   !(resource has requiresAnySlugs)
        || principal.permSlugs.containsAny(resource.requiresAnySlugs) )
};


// ============ API INVOKE (context-driven requirements from SDK) ============
permit(principal, action == Action::"api:invoke", resource)
when {
    (   !(context has requiresAnySlugs)
        || principal.permSlugs.containsAny(context.requiresAnySlugs) )
    &&
    (   !(context has requiresAnyConstraintPairs)
        || principal.permConstraintPairs.containsAny(context.requiresAnyConstraintPairs) )
};


// ============ API INVOKE (Tenant-Scoped) ============
forbid(principal, action == Action::"api:invoke", resource)
when {
    (resource has tenantId && ( !(principal has tenantId) || principal.tenantId != resource.tenantId ))
    ||
    ((context has tenantId) && ( !(principal has tenantId) || principal.tenantId != context.tenantId ))
};
