package terraform.tags

required_tags := {"env", "owner"}

deny[msg] {
  resource := input.resource_changes[_]

  # Only check resources being created or updated
  action := resource.change.actions[_]
  action == "create" or action == "update"

  tags := resource.change.after.tags
  missing := required_tags - {k | tags[k]}

  count(missing) > 0

  msg := sprintf(
    "Resource '%s' (%s) is missing required tags: %v",
    [resource.name, resource.type, missing]
  )
}
