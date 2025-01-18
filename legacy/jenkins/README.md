# Installing Jenkins

## Take a [docker-compose](https://github.com/jenkinsci/docker/blob/master/README.md) image
For example, from 
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


