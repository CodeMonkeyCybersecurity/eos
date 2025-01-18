# Installing Jenkins

## If you haven't already, [install docker](https://github.com/CodeMonkeyCybersecurity/eos/tree/main/legacy/docker)

## Take a [docker-compose](https://github.com/jenkinsci/docker/blob/master/README.md) image
For example: 
```
services:
  jenkins:
    image: jenkins/jenkins:lts
    ports:
      - "9080:8080" # default is 8080, but our 'helen' repo listens on 8080, so we have changed to 9080
    volumes:
      - jenkins_home:/var/jenkins_home
  ssh-agent:
    image: jenkins/ssh-agent
volumes:
  jenkins_home:
```

## Create a directory to install it locally 
```
mkdir -p $HOME/jenkins
nano $HOME/jenkins/docker-compose.yaml
```

Paste the docker compose configuration given above, then save and exit

## start up Jenkins 
```
cd /$HOME/jenkins
docker compose up -d
```

## verify it's installed properly
Check the docker image
```
docker ps
```

Then try to access it via the brower 
``` <hostname>:9080 ```
