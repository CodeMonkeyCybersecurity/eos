package infra

deny[msg] {
  input.resource.kind == "NetworkPolicy"
  not input.resource.spec.policyTypes[_] == "Egress"
  msg := "all NetworkPolicies must define an Egress rule"
}