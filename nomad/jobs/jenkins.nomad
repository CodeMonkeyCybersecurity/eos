# Jenkins Nomad Job Template  
# Managed by Eos - Do not edit manually

variable "port" {
  type = number
  default = 8080
  description = "Jenkins HTTP port"
}

variable "datacenter" {
  type = string
  default = "dc1"
  description = "Nomad datacenter"
}

variable "data_path" {
  type = string
  default = "/opt/jenkins/data"
  description = "Jenkins data directory"
}

variable "admin_password" {
  type = string
  default = ""
  description = "Jenkins admin password (if empty, use initial admin password)"
}

job "jenkins" {
  datacenters = [var.datacenter]
  type = "service"
  
  group "jenkins" {
    count = 1
    
    network {
      port "http" { 
        to = var.port
      }
      port "agent" {
        to = 50000
      }
    }
    
    volume "jenkins_data" {
      type = "host"
      source = "jenkins_data"
      read_only = false
    }
    
    task "jenkins" {
      driver = "docker"
      
      config {
        image = "jenkins/jenkins:lts"
        ports = ["http", "agent"]
        
        volumes = [
          "local/jenkins.yaml:/var/jenkins_home/casc_configs/jenkins.yaml"
        ]
      }
      
      volume_mount {
        volume = "jenkins_data"
        destination = "/var/jenkins_home"
      }
      
      template {
        data = <<EOF
jenkins:
  systemMessage: "Jenkins managed by Eos\n\n"
  numExecutors: 2
  mode: NORMAL
  securityRealm:
    local:
      allowsSignup: false
      users:
       - id: "admin"
         password: "{{ var.admin_password }}"
  authorizationStrategy:
    globalMatrix:
      permissions:
        - "Overall/Administer:admin"
        - "Overall/Read:authenticated"
  
unclassified:
  location:
    url: "http://localhost:{{ var.port }}/"
    
security:
  queueItemAuthenticator:
    authenticators:
    - global:
        strategy: triggeringUsersAuthorizationStrategy
EOF
        destination = "local/jenkins.yaml"
      }
      
      service {
        name = "jenkins"
        port = "http"
        
        tags = [
          "ci-cd",
          "automation", 
          "eos-managed"
        ]
        
        check {
          type = "http"
          path = "/login"
          interval = "10s"
          timeout = "3s"
        }
      }
      
      resources {
        cpu = 500
        memory = 1024
      }
      
      env {
        JAVA_OPTS = "-Djenkins.install.runSetupWizard=false"
        CASC_JENKINS_CONFIG = "/var/jenkins_home/casc_configs"
      }
    }
  }
}