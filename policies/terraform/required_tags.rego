package terraform.tags

required_tags := {"env", "owner"}

deny[msg] if {
  resource := input.values.root_module.resources[_]

  # Only check resources that support tags
  tags := resource.values.tags

  missing := required_tags - {k | tags[k] != null}

  count(missing) > 0

  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [resource.name, resource.type, missing]
  )
}

