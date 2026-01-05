package main

required_tags := {"env", "owner"}

########################################
# Entry point
########################################
deny contains msg if {
  res := all_resources[_]
  missing := missing_tags(res)
  count(missing) > 0
  msg := format_msg(res, missing)
}

########################################
# Recursive resource discovery
########################################
all_resources contains res if {
  walk_module(input.values.root_module, res)
}

walk_module(module, res) if {
  res := module.resources[_]
}

walk_module(module, res) if {
  child := module.child_modules[_]
  walk_module(child, res)
}

########################################
# Helpers
########################################
missing_tags(res) = missing if {
  tags := res.values.tags
  missing := required_tags - {k | tags[k] != null}
}

format_msg(res, missing) = msg if {
  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [res.name, res.type, missing]
  )
}
