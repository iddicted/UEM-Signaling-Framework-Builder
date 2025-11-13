#!/bin/zsh --no-rcs

# Non-interactive cleanup script for UEM Signaling Framework Builder objects
# This script deletes all Extension Attributes and Smart Groups created by the main script
# Usage: ./cleanup_uem_objects_cli.sh [--confirm]

# Check for confirmation flag
if [[ "$1" != "--confirm" ]]; then
    echo "################################################"
    echo "# UEM Signaling Framework Builder - CLEANUP   #"
    echo "################################################"
    echo ""
    echo "⚠️  WARNING: This will delete ALL Extension Attributes and Smart Groups"
    echo "    created by the UEM Signaling Framework Builder script."
    echo ""
    echo "Usage: $0 --confirm"
    echo ""
    echo "Add --confirm flag to proceed with cleanup."
    exit 1
fi

# Use same authentication variables as main script
jamf_pro_url="${JAMF_PRO_URL}"
client_id="${JAMF_CLIENT_ID_UEMSFB}"
client_secret="${JAMF_CLIENT_SECRET_UEMSFB}"

# Check if credentials are available
if [[ -z "$jamf_pro_url" || -z "$client_id" || -z "$client_secret" ]]; then
    echo "ERROR: Missing required environment variables:"
    echo "  - JAMF_PRO_URL"
    echo "  - JAMF_CLIENT_ID_UEMSFB" 
    echo "  - JAMF_CLIENT_SECRET_UEMSFB"
    echo ""
    echo "Please set these environment variables and try again."
    exit 1
fi

# Ensure URL has https
if [[ $jamf_pro_url != "https://"* ]]; then 
    jamf_pro_url="https://$jamf_pro_url"
fi

#### AUTHENTICATION ####
getAccessToken() {
    echo "INFO: Retrieving access token..."
    current_epoch=$(date +%s)
	response=$(curl --silent --location --request POST "${jamf_pro_url}/api/oauth/token" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "client_id=${client_id}" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_secret=${client_secret}")
    access_token=$(echo "$response" | jq -r '.access_token')
    token_expires_in=$(echo "$response" | jq -r '.expires_in')
    token_expiration_epoch=$(($current_epoch + $token_expires_in - 1))
	if [[ "$response" == *error* ]]; then
		echo "ERROR: Failed to retrieve access token."
		echo "Response: $response"
		exit 1
	fi
	echo "SUCCESS: Access token retrieved successfully."
}

checkTokenExpiration() {
    current_epoch=$(date +%s)
    buffer_time=300
    expiration_with_buffer=$((token_expiration_epoch - buffer_time))
    
    if [[ $expiration_with_buffer -ge $current_epoch ]]
    then
        time_remaining=$((token_expiration_epoch - current_epoch))
        echo "INFO: Token valid for $time_remaining more seconds"
    else
        echo "INFO: Getting new token"
        getAccessToken
    fi
}

#### CLEANUP FUNCTIONS ####

# Delete Computer Extension Attributes
cleanup_computer_eas() {
    echo ""
    echo "=== Cleaning up Computer Extension Attributes ==="
    
    # Get all computer EAs that match our naming pattern using XML API (more reliable)
    response=$(curl --silent --request GET \
        --url "$jamf_pro_url/JSSResource/computerextensionattributes" \
        --header "Authorization: Bearer $access_token" \
        --header "Accept: application/xml")
    
    # Parse XML response and get count
    ea_count=$(echo "$response" | xpath -q -e 'count(//computer_extension_attribute[contains(name, "JSC macOS Threat-Prevention-Policy:")])' 2>/dev/null || echo "0")
    
    if [[ $ea_count -gt 0 ]]; then
        echo "Found $ea_count Computer Extension Attributes to delete"
        
        # Debug: Show first few lines of XML response to understand structure
        echo "DEBUG: First 10 lines of Computer EA XML response:"
        echo "$response" | head -10
        
        # Parse the single-line XML format for Computer Extension Attributes
        parsed_eas=$(echo "$response" | grep -o '<computer_extension_attribute><id>[^<]*</id><name>JSC macOS Threat-Prevention-Policy:[^<]*</name>' | sed 's/<computer_extension_attribute><id>\([^<]*\)<\/id><name>\([^<]*\)<\/name>/\1|\2/')
        echo "DEBUG: Parsed EAs: $parsed_eas"
        
        # Process EAs one by one using XML parsing
        while IFS='|' read -r ea_id ea_name; do
            if [[ -n "$ea_id" && -n "$ea_name" ]]; then
                echo "Deleting Computer EA: $ea_name (ID: $ea_id)"
                
                delete_status=$(curl --silent -w "%{http_code}" -o /dev/null --request DELETE \
                    --url "$jamf_pro_url/JSSResource/computerextensionattributes/id/$ea_id" \
                    --header "Authorization: Bearer $access_token")
                    
                if [[ "$delete_status" -eq 200 ]]; then
                    echo "✅ Successfully deleted EA: $ea_name"
                else
                    echo "❌ Failed to delete EA: $ea_name (Status: $delete_status)"
                fi
                sleep 0.3
            fi
        done <<< "$parsed_eas"
    else
        echo "No Computer Extension Attributes found to delete."
    fi
}

# Delete Computer Smart Groups
cleanup_computer_groups() {
    echo ""
    echo "=== Cleaning up Computer Smart Groups ==="
    
    # Get all computer smart groups that match our naming pattern
    response=$(curl --silent --request GET \
        --url "$jamf_pro_url/api/v2/computer-groups/smart-groups?page=0&page-size=200" \
        --header "Authorization: Bearer $access_token")
    
    # Get count first
    group_count=$(echo "$response" | jq -r '.results[] | select(.name | contains("JSC Threat-Prevention-Policy:")) | .id' | wc -l | tr -d ' ')
    
    if [[ $group_count -gt 0 ]]; then
        echo "Found $group_count Computer Smart Groups to delete"
        
        # Process groups one by one using here-string to avoid subshell
        while IFS='|' read -r group_id group_name; do
            if [[ -n "$group_id" && -n "$group_name" ]]; then
                echo "Deleting Computer Smart Group: $group_name (ID: $group_id)"
                
                delete_status=$(curl --silent -w "%{http_code}" -o /dev/null --request DELETE \
                    --url "$jamf_pro_url/api/v2/computer-groups/smart-groups/$group_id" \
                    --header "Authorization: Bearer $access_token")
                    
                if [[ "$delete_status" -eq 204 ]]; then
                    echo "✅ Successfully deleted Smart Group: $group_name"
                else
                    echo "❌ Failed to delete Smart Group: $group_name (Status: $delete_status)"
                fi
                sleep 0.3
            fi
        done <<< "$(echo "$response" | jq -r '.results[] | select(.name | contains("JSC Threat-Prevention-Policy:")) | "\(.id)|\(.name)"')"
    else
        echo "No Computer Smart Groups found to delete."
    fi
}

# Delete Mobile Device Extension Attributes
cleanup_mobile_eas() {
    echo ""
    echo "=== Cleaning up Mobile Device Extension Attributes ==="
    
    # Get all mobile device EAs that match our naming pattern with cache-busting
    response=$(curl --silent --request GET \
        --url "$jamf_pro_url/api/v1/mobile-device-extension-attributes?page=0&page-size=200&_=$(date +%s)" \
        --header "Authorization: Bearer $access_token" \
        --header "Cache-Control: no-cache")
    
    # Get count first
    ea_count=$(echo "$response" | jq -r '.results[] | select(.name | contains("JSC iOS Threat-Prevention-Policy:")) | .id' | wc -l | tr -d ' ')
    
    if [[ $ea_count -gt 0 ]]; then
        echo "Found $ea_count Mobile Device Extension Attributes to delete"
        
        # Process EAs one by one using here-string to avoid subshell
        while IFS='|' read -r ea_id ea_name; do
            if [[ -n "$ea_id" && -n "$ea_name" ]]; then
                echo "Deleting Mobile Device EA: $ea_name (ID: $ea_id)"
                
                delete_status=$(curl --silent -w "%{http_code}" -o /dev/null --request DELETE \
                    --url "$jamf_pro_url/api/v1/mobile-device-extension-attributes/$ea_id" \
                    --header "Authorization: Bearer $access_token")
                    
                if [[ "$delete_status" -eq 204 ]]; then
                    echo "✅ Successfully deleted EA: $ea_name"
                else
                    echo "❌ Failed to delete EA: $ea_name (Status: $delete_status)"
                fi
                sleep 0.3
            fi
        done <<< "$(echo "$response" | jq -r '.results[] | select(.name | contains("JSC iOS Threat-Prevention-Policy:")) | "\(.id)|\(.name)"')"
    else
        echo "No Mobile Device Extension Attributes found to delete."
    fi
}

# Delete Mobile Device Smart Groups
cleanup_mobile_groups() {
    echo ""
    echo "=== Cleaning up Mobile Device Smart Groups ==="
    
    # Get all mobile device smart groups using XML API (more reliable for cleanup)
    response=$(curl --silent --request GET \
        --url "$jamf_pro_url/JSSResource/mobiledevicegroups" \
        --header "Authorization: Bearer $access_token" \
        --header "Accept: application/xml")
    
    # Parse XML and get count of smart groups with our naming pattern
    group_count=$(echo "$response" | xpath -q -e 'count(//mobile_device_group[contains(name, "JSC Threat-Prevention-Policy:") and is_smart="true"])' 2>/dev/null || echo "0")
    
    if [[ $group_count -gt 0 ]]; then
        echo "Found $group_count Mobile Device Smart Groups to delete"
        
        # Debug: Show first few lines of XML response to understand structure
        echo "DEBUG: First 10 lines of XML response:"
        echo "$response" | head -10
        
        # Parse the single-line XML format
        parsed_groups=$(echo "$response" | grep -o '<mobile_device_group><id>[^<]*</id><name>JSC Threat-Prevention-Policy:[^<]*</name><is_smart>true</is_smart></mobile_device_group>' | sed 's/<mobile_device_group><id>\([^<]*\)<\/id><name>\([^<]*\)<\/name><is_smart>true<\/is_smart><\/mobile_device_group>/\1|\2/')
        echo "DEBUG: Parsed groups: $parsed_groups"
        
        # Process groups using XML parsing
        while IFS='|' read -r group_id group_name; do
            if [[ -n "$group_id" && -n "$group_name" ]]; then
                echo "Deleting Mobile Device Smart Group: $group_name (ID: $group_id)"
                
                delete_status=$(curl --silent -w "%{http_code}" -o /dev/null --request DELETE \
                    --url "$jamf_pro_url/JSSResource/mobiledevicegroups/id/$group_id" \
                    --header "Authorization: Bearer $access_token")
                    
                if [[ "$delete_status" -eq 200 ]]; then
                    echo "✅ Successfully deleted Smart Group: $group_name"
                else
                    echo "❌ Failed to delete Smart Group: $group_name (Status: $delete_status)"
                fi
                sleep 0.3
            fi
        done <<< "$parsed_groups"
    else
        echo "No Mobile Device Smart Groups found to delete."
    fi
}

#### MAIN EXECUTION ####
echo "################################################"
echo "# UEM Signaling Framework Builder - CLEANUP   #"
echo "################################################"
echo ""
echo "Connecting to: $jamf_pro_url"

# Initialize token
access_token=""
token_expiration_epoch="0"
checkTokenExpiration

echo ""
echo "Starting cleanup process..."

# Clean up all objects (Smart Groups first due to EA dependencies)
cleanup_computer_groups
checkTokenExpiration
cleanup_mobile_groups
checkTokenExpiration
cleanup_computer_eas
checkTokenExpiration
cleanup_mobile_eas

echo ""
echo "################################################"
echo "✅ Cleanup completed!"
echo "################################################"
echo ""
echo "All UEM Signaling Framework Builder objects have been removed."
echo "You can now run the main script for testing."