package main

required_tags := {"env", "owner"}

# Entry point: iterate all resources recursively
deny contains msg if {
  resource := all_resources[_]
  missing := missing_tags(resource)
  count(missing) > 0
  msg := format_msg(resource, missing)
}

# -------------------------
# Recursive resource walker
# -------------------------
all_resources[resource] {
  walk_module(input.values.root_module, resource)
}

walk_module(module, resource) {
  resource := module.resources[_]
}

walk_module(module, resource) {
  child := module.child_modules[_]
  walk_module(child, resource)
}

# -------------------------
# Helpers
# -------------------------
missing_tags(resource) = missing if {
  tags := resource.values.tags
  missing := required_tags - {k | tags[k] != null}
}

format_msg(resource, missing) = msg if {
  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [resource.name, resource.type, missing]
  )
}
