#!/bin/bash

# Function to get user input for API token, zone ID, etc.
get_user_input() {
    read -p "Enter your Hetzner API token: " API_TOKEN
    read -p "Enter your Zone ID: " ZONE_ID
}

# Function to create a DNS record
create_record() {
    read -p "Enter the subdomain: " NAME
    read -p "Enter the IP address (value): " VALUE
    read -p "Enter the record type (A, CNAME, etc.) [default A]: " TYPE
    TYPE=${TYPE:-A}
    read -p "Enter the TTL [default 3600]: " TTL
    TTL=${TTL:-3600}

    curl -X POST "https://dns.hetzner.com/api/v1/records" \
        -H "Auth-API-Token: $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
              \"zone_id\": \"$ZONE_ID\",
              \"type\": \"$TYPE\",
              \"name\": \"$NAME\",
              \"value\": \"$VALUE\",
              \"ttl\": $TTL
            }"
    echo "Record created."
}

# Function to update a DNS record
update_record() {
    read -p "Enter the Record ID to update: " RECORD_ID
    read -p "Enter the new IP address (value): " VALUE
    read -p "Enter the new TTL [default 3600]: " TTL
    TTL=${TTL:-3600}

    curl -X PUT "https://dns.hetzner.com/api/v1/records/$RECORD_ID" \
        -H "Auth-API-Token: $API_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
              \"value\": \"$VALUE\",
              \"ttl\": $TTL
            }"
    echo "Record updated."
}

# Function to delete a DNS record
delete_record() {
    read -p "Enter the Record ID to delete: " RECORD_ID

    curl -X DELETE "https://dns.hetzner.com/api/v1/records/$RECORD_ID" \
        -H "Auth-API-Token: $API_TOKEN"
    echo "Record deleted."
}

# Function to list DNS records in a zone
list_records() {
    curl -X GET "https://dns.hetzner.com/api/v1/records?zone_id=$ZONE_ID" \
        -H "Auth-API-Token: $API_TOKEN" | jq .
}

# Main script
echo "DNS Management Script"
echo "======================"
get_user_input

PS3="What would you like to do? "
options=("Create Record" "Update Record" "Delete Record" "List Records" "Quit")
select opt in "${options[@]}"; do
    case $opt in
        "Create Record")
            create_record
            ;;
        "Update Record")
            update_record
            ;;
        "Delete Record")
            delete_record
            ;;
        "List Records")
            list_records
            ;;
        "Quit")
            break
            ;;
        *) echo "Invalid option $REPLY";;
    esac
done
