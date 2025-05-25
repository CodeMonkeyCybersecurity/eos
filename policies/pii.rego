package pii

default allow = false

allow {
  # Only redacted logs may contain “email” fields
  not input.log.message[_] == "email"
}

violation[msg] {
  input.log.message[_] == "email"
  msg := "PII field ‘email’ found in log"
}