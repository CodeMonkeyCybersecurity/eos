storage "raft" {
  path    = "/vault/data"
  node_id = "vault-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8179"
}

api_addr      = "https://vault:8179"
cluster_addr  = "https://vault:8201"
disable_mlock = true
ui            = true
