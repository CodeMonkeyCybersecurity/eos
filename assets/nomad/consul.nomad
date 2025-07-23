job "consul" {
  datacenters = ["dc1"]
  type        = "service"

  group "consul" {
    count = 1

    network {
      port "http" {
        static = 8500
      }
      port "dns" {
        static = 8600
      }
      port "serf_lan" {
        static = 8301
      }
      port "serf_wan" {
        static = 8302
      }
      port "server" {
        static = 8300
      }
    }

    task "consul" {
      driver = "docker"

      config {
        image = "hashicorp/consul:latest"
        ports = ["http", "dns", "serf_lan", "serf_wan", "server"]
        
        volumes = [
          "local/consul.json:/consul/config/consul.json",
          "consul-data:/consul/data"
        ]

        logging {
          type = "json-file"
          config {
            max-size = "10m"
            max-file = "3"
          }
        }
      }

      env {
        CONSUL_BIND_INTERFACE = "eth0"
        CONSUL_CLIENT_INTERFACE = "eth0"
      }

      template {
        data = <<EOH
{
  "datacenter": "dc1",
  "data_dir": "/consul/data",
  "log_level": "INFO",
  "node_name": "consul-server-1",
  "server": true,
  "bootstrap_expect": 1,
  "ui_config": {
    "enabled": true
  },
  "client_addr": "0.0.0.0",
  "bind_addr": "{{ GetInterfaceIP \"eth0\" }}",
  "advertise_addr": "{{ GetInterfaceIP \"eth0\" }}",
  "ports": {
    "http": 8500,
    "dns": 8600,
    "serf_lan": 8301,
    "serf_wan": 8302,
    "server": 8300
  },
  "connect": {
    "enabled": true
  },
  "acl": {
    "enabled": false,
    "default_policy": "allow"
  },
  "performance": {
    "raft_multiplier": 1
  },
  "telemetry": {
    "prometheus_retention_time": "30s",
    "disable_hostname": true
  },
  "dns_config": {
    "enable_truncate": true,
    "only_passing": true
  },
  "limits": {
    "http_max_conns_per_client": 200
  },
  "services": {
    "consul": {
      "name": "consul",
      "tags": ["consul", "service-discovery"],
      "port": 8500,
      "check": {
        "id": "consul-ui",
        "name": "Consul UI",
        "http": "http://localhost:8500/ui/",
        "interval": "30s",
        "timeout": "5s"
      }
    }
  }
}
EOH
        destination = "local/consul.json"
      }

      resources {
        cpu    = 500
        memory = 512
      }

      service {
        name = "consul"
        port = "http"
        tags = ["service-discovery", "ui"]

        check {
          type     = "http"
          path     = "/v1/status/leader"
          interval = "30s"
          timeout  = "5s"
        }
      }

      service {
        name = "consul-dns"
        port = "dns"
        tags = ["service-discovery", "dns"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}