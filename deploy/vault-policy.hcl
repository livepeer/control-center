path "transit/encrypt/orchestrator-*" {
  capabilities = ["create", "update"]
}

path "transit/decrypt/orchestrator-*" {
  capabilities = ["update"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Let deployment preflight check this token's Transit access without root access
# or reading or writing application secrets.
path "sys/capabilities-self" {
  capabilities = ["update"]
}
