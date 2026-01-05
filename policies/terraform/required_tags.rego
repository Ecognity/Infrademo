package main

required_tags := {"env", "owner"}

########################################
# Entry point
########################################
deny contains msg if {
  r := all_resources[_]
  missing := missing_tags(r)
  count(missing) > 0
  msg := format_msg(r, missing)
}

########################################
# Collect ALL resources (recursive)
########################################
all_resources contains r if {
  r := input.values.root_module.resources[_]
}

all_resources contains r if {
  child := input.values.root_module.child_modules[_]
  r := child.resources[_]
}

all_resources contains r if {
  child := input.values.root_module.child_modules[_]
  grandchild := child.child_modules[_]
  r := grandchild.resources[_]
}

########################################
# Helpers
########################################
missing_tags(r) = missing if {
  tags := object.get(r.values, "tags", {})
  missing := required_tags - {k | tags[k] != null}
}

format_msg(r, missing) = msg if {
  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [r.name, r.type, missing]
  )
}
