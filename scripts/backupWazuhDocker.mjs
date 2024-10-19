#!/usr/bin/env zx

// Define backup directory and timestamp
const BACKUP_DIR = '/path/to/backup';
const TIMESTAMP = new Date().toISOString().replace(/[-:.T]/g, '').split('.')[0]; // Format: YYYYMMDD_HHMMSS
const BACKUP_FILE = `${BACKUP_DIR}/wazuh_backup_${TIMESTAMP}.tar.gz`;

// Create backup directory if it doesn't exist
await $`mkdir -p ${BACKUP_DIR}`;

// Backup Wazuh Manager configuration
console.log('Backing up Wazuh Manager configuration...');
await $`docker exec -u root aef5e791a447 tar czf /tmp/wazuh_manager_config.tar.gz /var/ossec/etc`;
await $`docker cp aef5e791a447:/tmp/wazuh_manager_config.tar.gz ${BACKUP_DIR}`;

// Backup Wazuh API configuration (if applicable)
console.log('Backing up Wazuh API configuration...');
await $`docker exec -u root aef5e791a447 tar czf /tmp/wazuh_api_config.tar.gz /var/ossec/api/config`;
await $`docker cp aef5e791a447:/tmp/wazuh_api_config.tar.gz ${BACKUP_DIR}`;

// Backup Wazuh Dashboard configuration
console.log('Backing up Wazuh Dashboard configuration...');
await $`docker exec -u root aef5e791a447 tar czf /tmp/wazuh_dashboard_config.tar.gz /usr/share/wazuh-dashboard/data/wazuh/config`;
await $`docker cp aef5e791a447:/tmp/wazuh_dashboard_config.tar.gz ${BACKUP_DIR}`;

// Backup Elasticsearch data (if applicable)
console.log('Backing up Elasticsearch data...');
await $`docker exec -u root elasticsearch_container_name tar czf /tmp/elasticsearch_data.tar.gz /usr/share/elasticsearch/data`;
await $`docker cp elasticsearch_container_name:/tmp/elasticsearch_data.tar.gz ${BACKUP_DIR}`;

// Create a single archive file for all backups
await $`tar czf ${BACKUP_FILE} -C ${BACKUP_DIR} .`;

// Clean up temporary files
await $`rm ${BACKUP_DIR}/*.tar.gz`;

console.log(`Backup completed: ${BACKUP_FILE}`);
