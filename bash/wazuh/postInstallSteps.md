# Wazuh post install steps

Now we have installed Wazuh, we need to change the default passwords and verify it's working correctly before [exposing it to the internet](https://github.com/CodeMonkeyCybersecurity/hetcate.git).

Thank you to Wazuh for these [instructions](https://documentation.wazuh.com/current/deployment-options/docker/wazuh-container.html#change-pwd-existing-usr).

There are three default users whose passwords we need to change:
* Wazuh indexer users `admin` and `kibanaserver`
* Wazuh API user `wazuh-wui`
