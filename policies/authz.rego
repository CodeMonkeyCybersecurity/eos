package authz

default allow = false

# Only “admin” or users on the same org as the resource can call sensitive endpoints
allow {
  input.method == "DELETE"                  # e.g. DELETE /models/{id}
  allowed_roles := {"superadmin", "security-lead"}
  allowed_roles[input.user.role]
}

allow {
  input.method == "GET"
  input.user.org == input.resource.org    # only same-org reads
}