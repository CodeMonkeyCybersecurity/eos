// Package delphi contains embedded YAML templates for the “delphi” pack
// and its StackStorm rule. These can be referenced by the Eos CLI when
// scaffolding or installing the pack.
package stackstorm

// PackYAML is the content of pack.yaml for the “delphi” pack.
const PackYAML = `name: delphi
description: "Delphi alert processing pack"
version: "0.1.0"
author: Code Monkey Cybersecurity
email: main@cybermonkey.net.au
`

// WazuhWebhookRuleYML is the StackStorm rule (wazuh_webhook.yml) that
// catches POSTs from Wazuh and writes them to a log file.
const WazuhWebhookRuleYML = `---
name: wazuh_webhook
pack: delphi
description: "Catch POSTs from Wazuh and trigger pipeline"
enabled: true
trigger:
  type: core.st2.webhook
  parameters:
    url: wazuh_alert
criteria:
  trigger.body.rule.level:
    type: "greaterthan"
    pattern: 2
action:
  ref: core.local
  parameters:
    cmd: "echo '{{ trigger.body | to_json_string }}' >> /var/log/stackstorm/wazuh_test.log"
`
