#!/bin/zsh --no-rcs

# This script creates Extension Attributes and Smart Groups in Jamf Pro for use with Jamf Security Cloud UEM signaling.
# It uses Swift Dialog to present a user interface for selecting which EAs and groups to create.
# The script requires Jamf Pro API credentials:
# - JAMF_PRO_URL: The base URL of your Jamf Pro instance (e.g., https://yourdomain.jamfcloud.com)
# - JAMF_CLIENT_ID_FULL_ADMIN: The client ID of a Jamf Pro API user
# - JAMF_CLIENT_SECRET_FULL_ADMIN: The client secret of a Jamf Pro API user
## Required Permissions:
# - Computer Extension Attributes: Create, Read
# - Mobile Device Extension Attributes: Create, Read
# - Computer Groups: Create, Read
# - Mobile Device Groups: Create, Read

################################################################################
##### CONFIGURABLE VARIABLES #####



jamf_pro_url="${JAMF_PRO_URL}" # Set JAMF_PRO_URL in your environment
client_id="${JAMF_CLIENT_ID_UEMSFB}"  # Set JAMF_CLIENT_ID in your environment
client_secret="${JAMF_CLIENT_SECRET_UEMSFB}" # Set JAMF_CLIENT_SECRET in your environment
threat_prevention_policies_macOS=("Phishing" "Malware network traffic" "Cryptojacking" "Spam" "Third-party app store traffic" "Vulnerable app installed" "Vulnerable OS (major)" "App inactivity" "Vulnerable OS (minor)"  "Out-of-date OS" "User password disabled")
threat_prevention_policies_iOS=("Phishing" "Data Leaks" "Malware network traffic" "Cryptojacking" "Spam" "Third-party app store traffic" "Malware" "Sideloaded app installed" "Vulnerable app installed" "Dangerous certificate" "Adversary-in-the-Middle" "Risky hotspots" "Jailbreak" "Vulnerable OS (major)" "App inactivity" "Lock screen disabled" "Risky iOS Profile" "Vulnerable OS (minor)" "Out-of-date OS")
# threat_prevention_policies_macOS=("test1" "test2")
# threat_prevention_policies_iOS=("mobiletest1" "mobiletest2")
#################################

### Swift Dialog variables ###
# Path to Swift Dialog binary
messageFont="size=20,name=HelveticaNeue"
titleFont="weight=bold,size=30,name=HelveticaNeue-Bold"
icon="https://github.com/iddicted/UEM-Signaling-Framework-Builder/blob/main/Images/Logo.png?raw=true"
local_icon="/tmp/UEM_SFB_logo.png" # Local path to the logo file
#### End Configuration Variables ####
#################################

#### LOGGING SETUP (sh compatible) ####
LOG_DIR="$HOME/Library/Logs/UEM_Signaling_Framework_Builder"
LOG_FILE="$LOG_DIR/UEM_SF_$(date +'%Y-%m-%d_%H-%M-%S').log"
mkdir -p "$LOG_DIR" # Create the Log directory if it doesn't exist
# Create a temporary named pipe (a special type of file)
# and ensure it gets cleaned up when the script exits.
TMP_DIR=$(mktemp -d)
PIPE="$TMP_DIR/logpipe"
mkfifo "$PIPE"
trap 'rm -rf "$TMP_DIR"' EXIT
# Start a tee process in the background to read from the pipe
# and send output to the log file.
tee -a "$LOG_FILE" < "$PIPE" &
# Redirect all script output (stdout and stderr) to the pipe.
# The background tee process will catch it and do its job.
exec > "$PIPE" 2>&1
echo "############ Starting Recovery Lock Manager script ############"
echo "Logging output to: $LOG_FILE"
#### END LOGGING SETUP ####


################################################################################ FUNCTIONS ################################################################################
#### API AUTHENTICATION ####
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
		echo "ERROR: Failed to retrieve access token or expiration time."
        #echo "DEBUG: Full response: $response"
		exit 1
	fi
	echo "SUCCESS: Access token retrieved successfully."
	echo "INFO: Token expires in: $token_expires_in seconds"
}
checkTokenExpiration() {
    current_epoch=$(date +%s)
    # Add 300 seconds (5 minutes) buffer to renew token before it expires
    buffer_time=300
    expiration_with_buffer=$((token_expiration_epoch - buffer_time))
    
    if [[ $expiration_with_buffer -ge $current_epoch ]]
    then
        time_remaining=$((token_expiration_epoch - current_epoch))
        echo "INFO: Token valid for $time_remaining more seconds (expires at epoch: $token_expiration_epoch)"
    else
        if [[ $token_expiration_epoch -gt 0 ]]; then
            echo "INFO: Token expires soon or has expired, getting new token"
        else
            echo "INFO: No valid token available, getting new token"
        fi
        getAccessToken
    fi
}
invalidateToken() {
    echo "INFO: Invalidating access token..."
	responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${access_token}" $jamf_pro_url/api/v1/auth/invalidate-token -X POST -s -o /dev/null)
    if [[ ${responseCode} == 204 ]]
    then
        echo "SUCCESS: Token successfully invalidated"
        access_token=""
        token_expiration_epoch="0"
    elif [[ ${responseCode} == 401 ]]
    then
        echo "INFO: Token already invalid"
    else
        echo "ERROR: An unknown error occurred invalidating the token"
    fi
}

#### SWIFT DIALOG FUNCTIONS ####
# Download the logo file to have it available offline
downloadLogo() {
    curl -L -o "$local_icon" "$icon"
}

credentialPrompt() {
	echo "INFO: Prompting user for Jamf Pro credentials..."
    # Request JSON output and use the correct syntax for textfield options
    serverDetails=$(/usr/local/bin/dialog \
        --title "JCS UEM Signaling Framework Builder" \
        --message "Please enter your Jamf Pro details below:" \
        --textfield "Jamf Pro URL" --required \
        --textfield "Client ID" --required \
        --textfield "Client Secret" --required --secure \
        --icon "$local_icon" \
        --alignment "left" \
        --small \
        --button2 \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --json)
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        # Use jq to parse the JSON output
        jamf_pro_url=$(echo "$serverDetails" | jq -r '."Jamf Pro URL"')
        client_id=$(echo "$serverDetails" | jq -r '."Client ID"')
        client_secret=$(echo "$serverDetails" | jq -r '."Client Secret"')
    else
        echo "User cancelled"
        exit 0
    fi
    
    # Ensure the URL starts with https://
    if [[ $jamf_pro_url != "https://"* ]]; then 
        jamf_pro_url="https://$jamf_pro_url"
    fi
}
# Function to check if Swift Dialog is installed, if not it downloads and installs it
install_swift_dialog() {
	echo "###### SWIFT DIALOG INSTALLATION ######"
	echo "Checking if SwiftDialog is installed"
	if [[ -e "/usr/local/bin/dialog" ]]; then
		echo "SwiftDialog is already installed"
        echo "Version: $(/usr/local/bin/dialog --version)"
        echo ""
	else
		echo "SwiftDialog Not installed, downloading and installing"
		/usr/bin/curl https://github.com/swiftDialog/swiftDialog/releases/download/v2.5.6/dialog-2.5.6-4805.pkg -L -o /tmp/dialog-2.5.6-4805.pkg
		cd /tmp
		sudo /usr/sbin/installer -pkg dialog-2.5.6-4805.pkg -target /
	fi
}
select_macOS_TPPs_prompt() {
    # Prompt user to select an EA
    # when selecting all, all EAs checkboxes should be selected
    echo "###### SWIFT DIALOG PROMPT FOR macOS TPPs ######"
    
    # Build the dialog command dynamically
    dialog_cmd=(/usr/local/bin/dialog \
        --title "JCS UEM Signaling Framework Builder" \
        --message "Please select the Computer Extension Attributes you want to create:" \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --icon "$local_icon" \
        --checkboxstyle "switch,large" \
        --width 800 \
        --infobuttontext "Select All" \
        --button2 "Cancel")
    
    # Add checkboxes dynamically for each policy
    for policy in "${threat_prevention_policies_macOS[@]}"; do
        if [[ -n "$policy" ]]; then  # Only add non-empty policies
            dialog_cmd+=(--checkbox "$policy")
        fi
    done
    
    selectedTPPsMac=$("${dialog_cmd[@]}")
    local exit_code=$?
    
    if [[ $exit_code -eq 2 ]]; then
        echo "INFO: User cancelled the operation. Exiting."
        exit 0
    elif [[ $exit_code -eq 3 ]]; then
        echo "INFO: User selected 'Select All'."
        selectedTPPsMac=("${threat_prevention_policies_macOS[@]}")
        echo "INFO: Using all TPPs: ${selectedTPPsMac[@]}"
        echo ""
    else
        # Parse selected TPPs properly handling spaces in policy names
        temp_selected=()
        while IFS= read -r line; do
            if [[ "$line" =~ :[[:space:]]*\"true\" ]]; then
                policy_name=$(echo "$line" | cut -d '"' -f 2)
                temp_selected+=("$policy_name")
            fi
        done <<< "$selectedTPPsMac"
        selectedTPPsMac=("${temp_selected[@]}")
        echo "INFO: User selected the following TPPs: ${selectedTPPsMac[@]}"
        echo ""
    fi
}

select_iOS_TPPs_prompt() {
    # Prompt user to select an EA
    # when selecting all, all EAs checkboxes should be selected
    echo "###### SWIFT DIALOG PROMPT FOR iOS TPPs ######"
    
    # Build the dialog command dynamically
    dialog_cmd=(/usr/local/bin/dialog \
        --title "JCS UEM Signaling Framework Builder" \
        --message "Please select the Mobile Device Extension Attributes you want to create:" \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --icon "$local_icon" \
        --checkboxstyle "switch,large" \
        --width 800 \
        --button2 "Cancel" \
        --infobuttontext "Select All")
    
    # Add checkboxes dynamically for each policy
    for policy in "${threat_prevention_policies_iOS[@]}"; do
        if [[ -n "$policy" ]]; then  # Only add non-empty policies
            dialog_cmd+=(--checkbox "$policy")
        fi
    done
    
    selectedTPPsiOS=$("${dialog_cmd[@]}")
    local exit_code=$?
    
    if [[ $exit_code -eq 2 ]]; then
        echo "INFO: User cancelled the operation. Exiting."
        exit 0
    elif [[ $exit_code -eq 3 ]]; then
        echo "INFO: User selected 'Select All'."
        selectedTPPsiOS=("${threat_prevention_policies_iOS[@]}")
        echo "INFO: Using all TPPs: ${selectedTPPsiOS[@]}"
        echo ""
        return
    else
        # Parse selected TPPs properly handling spaces in policy names
        temp_selected=()
        while IFS= read -r line; do
            if [[ "$line" =~ :[[:space:]]*\"true\" ]]; then
                policy_name=$(echo "$line" | cut -d '"' -f 2)
                temp_selected+=("$policy_name")
            fi
        done <<< "$selectedTPPsiOS"
        selectedTPPsiOS=("${temp_selected[@]}")
        echo "INFO: User selected the following TPPs: ${selectedTPPsiOS[@]}"
        echo ""
    fi        
}
########################
# create extension attributes
create_computer_extension_attribute() {
    # Use -w to write the HTTP status code to stdout and -o to discard the response body
    http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
        --url "$jamf_pro_url/api/v1/computer-extension-attributes" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json' \
        --header 'content-type: application/json' \
        --data "{
    \"dataType\": \"STRING\",
    \"enabled\": true,
    \"inventoryDisplayType\": \"EXTENSION_ATTRIBUTES\",
    \"inputType\": \"TEXT\",
    \"ldapExtensionAttributeAllowed\": false,
    \"name\": \"JSC macOS Threat-Prevention-Policy: $policy\",
    \"description\": \"Jamf Security Cloud Threat Prevention Policy for $policy Events\"
    }")
}
# create smart computer groups for EA 
create_computer_smart_group() {
    # Use -w to write the HTTP status code to stdout and -o to discard the response body
    http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
        --url "$jamf_pro_url/api/v2/computer-groups/smart-groups" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json' \
        --header 'content-type: application/json' \
        --data "{
            \"name\": \"JSC Threat-Prevention-Policy: $policy\",
            \"description\": \"Smart Group for devices matching Jamf Security Cloud Threat Prevention Policy: $policy\",
            \"criteria\": [
                {
                    \"name\": \"JSC macOS Threat-Prevention-Policy: $policy\",
                    \"value\": \"true\",
                    \"searchType\": \"is\",
                    \"andOr\": \"and\"
                }
            ],
            \"siteId\": \"-1\"
        }")
}
# create mobile device extension attributes
create_mobile_device_extension_attribute() {
    # Use -w to write the HTTP status code to stdout and -o to discard the response body
    http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
        --url "$jamf_pro_url/api/v1/mobile-device-extension-attributes" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json' \
        --header 'content-type: application/json' \
        --data "{
            \"dataType\": \"STRING\",
            \"inventoryDisplayType\": \"EXTENSION_ATTRIBUTES\",
            \"inputType\": \"TEXT\",
            \"ldapExtensionAttributeAllowed\": false,
            \"name\": \"JSC iOS Threat-Prevention-Policy: $policy\",
            \"description\": \"Jamf Security Cloud Threat Prevention Policy for $policy Events\"
            }")
}
# create smart mobile device groups for EA 
# Using new api to create mobile device smart group
create_mobile_device_smart_group() {
    echo "INFO: Creating mobile device smart group using JSON API with correct structure..."
    # echo "DEBUG: Policy name received: '$policy'"
    # echo "DEBUG: Full EA name will be: 'JSC iOS Threat-Prevention-Policy: $policy'"
    
    # Mobile device smart groups API doesn't support extensionAttributeId, must use name
    # But let's verify the EA exists and get its exact name from the system
    ea_id=$(get_mobile_device_ea_id "$policy")
    if [[ $? -eq 0 && -n "$ea_id" ]]; then
        # echo "DEBUG: EA verified to exist with ID $ea_id"
        # Get the exact EA name from the system to ensure perfect match
        ea_response=$(curl --silent --request GET \
            --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes/$ea_id" \
            --header "Authorization: Bearer ${access_token}")
        exact_ea_name=$(echo "$ea_response" | jq -r '.name')
        # echo "DEBUG: Using exact EA name from system: '$exact_ea_name'"
    else
        echo "WARNING: Could not verify EA, using constructed name"
        exact_ea_name="JSC iOS Threat-Prevention-Policy: $policy"
    fi
    
    # Create the JSON payload using the exact EA name from the system
    json_payload="{
        \"groupName\": \"JSC Threat-Prevention-Policy: $policy\",
        \"groupDescription\": \"Smart Group for devices matching Jamf Security Cloud Threat Prevention Policy: $policy\",
        \"criteria\": [
            {
                \"name\": \"$exact_ea_name\",
                \"value\": \"true\",
                \"searchType\": \"is\",
                \"andOr\": \"and\",
                \"priority\": 0
            }
        ],
        \"siteId\": \"-1\"
    }"
    
    # echo "DEBUG: JSON payload being sent:"
    # echo "$json_payload"
    
    response=$(curl --silent -w "\n%{http_code}" --request POST \
        --url "$jamf_pro_url/api/v1/mobile-device-groups/smart-groups?platform=false" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json' \
        --header 'content-type: application/json' \
        --data "$json_payload")
    
    # Extract status code (last line) and response body (everything else)
    http_status=$(echo "$response" | tail -n1)
    response_body=$(echo "$response" | sed '$d')
    
    # If JSON API fails, fall back to XML API
    if [[ "$http_status" -ne 201 ]]; then
        echo "WARNING: JSON API failed with status $http_status"
        # echo "DEBUG: Full JSON API response: $response_body"
        # echo "DEBUG: EA name being referenced: 'JSC iOS Threat-Prevention-Policy: $policy'"
        # echo "DEBUG: Group name: 'JSC Threat-Prevention-Policy: $policy'"
        echo "INFO: Falling back to XML API..."
        
        # Create XML payload for smart group creation
        xml_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <mobile_device_group>
            <name>JSC Threat-Prevention-Policy: $policy</name>
            <is_smart>true</is_smart>
            <criteria>
                <criterion>
                    <name>JSC iOS Threat-Prevention-Policy: $policy</name>
                    <priority>0</priority>
                    <and_or>and</and_or>
                    <search_type>is</search_type>
                    <value>true</value>
                </criterion>
            </criteria>
            <site>
                <id>-1</id>
            </site>
        </mobile_device_group>"
        
        # Create the group using XML API as fallback
        http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
            --url "$jamf_pro_url/JSSResource/mobiledevicegroups/id/0" \
            --header "Authorization: Bearer $access_token" \
            --header 'accept: application/xml' \
            --header 'content-type: application/xml' \
            --data "$xml_payload")
            
        if [[ "$http_status" -eq 201 ]]; then
            echo "INFO: Successfully created mobile device smart group using XML API fallback."
        fi
    else
        echo "INFO: Successfully created mobile device smart group using JSON API."
    fi
}
# Using old api: JSSResource/mobiledevicegroups/id/0 which needs to add an xml file to create a smart group
# create_mobile_device_smart_group() {
#     # Create XML payload for smart group creation
#     xml_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
#         <mobile_device_group>
#             <name>JSC Threat-Prevention-Policy: $policy</name>
#             <is_smart>true</is_smart>
#             <criteria>
#                 <criterion>
#                     <name>JSC iOS Threat-Prevention-Policy: $policy</name>
#                     <priority>0</priority>
#                     <and_or>and</and_or>
#                     <search_type>is</search_type>
#                     <value>true</value>
#                 </criterion>
#             </criteria>
#             <site>
#                 <id>-1</id>
#             </site>
#         </mobile_device_group>"
#     # Create the group
#     http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
#         --url "$jamf_pro_url/JSSResource/mobiledevicegroups/id/0" \
#         --header "Authorization: Bearer $access_token" \
#         --header 'accept: application/xml' \
#         --header 'content-type: application/xml' \
#         --data "$xml_payload")
# }
donePrompt() {
	echo "INFO: Showing Done Prompt."
	# Prompt user that action is completed
	/usr/local/bin/dialog \
	--title "JCS UEM Signaling Framework Builder" \
	--message "Action Completed.\n\nYou can now view your changes in Jamf Pro: $jamf_pro_url/" \
	--icon "$icon" \
	--alignment "left" \
	--small \
	--messagefont "$messageFont" \
	--titlefont "$titleFont" \
	--button1text "DONE" \
	--infobuttontext "Open Log" \
	--infobuttonaction "file://$LOG_FILE"
}

check_computer_ea_exists() {
    echo "INFO: Checking for Computer Extension Attribute '$ea_name'..."
    local encoded_ea_name
    encoded_ea_name=$(echo "$ea_name" | sed 's/ /%20/g') # replace spaces with %20 for URL encoding
    response=$(curl --silent --request GET \
    --url "$jamf_pro_url/api/v1/computer-extension-attributes?page=0&page-size=200&filter=name%3D%3D%22${encoded_ea_name}%22" \
    --header "Authorization: Bearer $access_token")

    # if total count is greater than 0, EA exists
    if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
        echo "INFO: Computer Extension Attribute with name '$ea_name' already exists. Skipping creation."
        return 1
    else
        echo "INFO: Computer Extension Attribute '$ea_name' not found."
        return 0
    fi
}

get_computer_group_info() {
    local encoded_group_name
    encoded_group_name=$(echo "$group_name" | sed 's/ /%20/g') # replace spaces with %20 for URL encoding
    response=$(curl --silent --request GET \
        --url "$jamf_pro_url/api/v2/computer-groups/smart-groups?page=0&page-size=100&sort=id%3Aasc&filter=name%3D%3D%22${encoded_group_name}%22" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json')

     # if total count is greater than 0, group exists
     if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
        echo "Smart Group already exists for Phishing. Skipping creation. Skipping creation."
        return 1
    else
        echo "INFO: Computer Smart Group not found. Creating..."
        return 0
    fi
}

check_mobile_device_ea_exists() {
    echo "INFO: Checking for Mobile Device Extension Attribute '$ea_name'..."
    local encoded_ea_name
    encoded_ea_name=$(echo "$ea_name" | sed 's/ /%20/g') # replace spaces with %20 for URL encoding
    response=$(curl --silent --request GET \
        --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes?page=0&page-size=200&filter=name%3D%3D%22${encoded_ea_name}%22" \
        --header "Authorization: Bearer ${access_token}")
    #echo "DEBUG: Response for checking Mobile Device EA existence: $response"
    # if total count is greater than 0, EA exists
    if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
        echo "INFO: Mobile Device Extension Attribute with name '$ea_name' already exists. Skipping creation."
        return 1
    else
        echo "INFO: Mobile Device Extension Attribute '$ea_name' not found."
        return 0
    fi
}

get_mobile_device_group_info() {
    # using older api to get mobile device groups
    local encoded_group_name
    encoded_group_name=$(echo "$group_name" | sed 's/ /%20/g')
    # get list of all mobile device groups (/api/v1/mobile-device-groups) and check if group exists
    mobile_device_groups=$(curl --silent --request GET \
        --url "$jamf_pro_url/api/v1/mobile-device-groups" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/json')
    # if group_name exists in the list, return 1
    if [[ $(echo "$mobile_device_groups" | jq -r --arg NAME "$group_name" '.[] | select(.name == $NAME) | .name' | wc -l) -gt 0 ]]; then
        echo "INFO: Mobile Device Smart Group with name '$group_name' already exists. Skipping creation."
        return 1
    else
        echo "INFO: Mobile Device Smart Group '$group_name' not found."
        return 0
    fi
}

# Function to get EA ID by name
get_mobile_device_ea_id() {
    local ea_name_to_check="JSC iOS Threat-Prevention-Policy: $1"
    local encoded_ea_name
    encoded_ea_name=$(echo "$ea_name_to_check" | sed 's/ /%20/g')
    response=$(curl --silent --request GET \
        --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes?page=0&page-size=200&filter=name%3D%3D%22${encoded_ea_name}%22" \
        --header "Authorization: Bearer ${access_token}")
    
    if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
        ea_id=$(echo "$response" | jq -r '.results[0].id')
        ea_name=$(echo "$response" | jq -r '.results[0].name')
        # echo "DEBUG: Found EA ID: $ea_id for name: '$ea_name'" >&2  # Send debug to stderr
        echo "$ea_id"  # Only return the ID to stdout
        return 0
    else
        echo "ERROR: Could not find EA ID for '$ea_name_to_check'" >&2
        return 1
    fi
}

# Function to verify EA exists before creating smart group
verify_mobile_device_ea_exists() {
    local ea_name_to_check="JSC iOS Threat-Prevention-Policy: $1"
    echo "INFO: Verifying Extension Attribute '$ea_name_to_check' exists..."
    local encoded_ea_name
    encoded_ea_name=$(echo "$ea_name_to_check" | sed 's/ /%20/g')
    response=$(curl --silent --request GET \
        --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes?page=0&page-size=200&filter=name%3D%3D%22${encoded_ea_name}%22" \
        --header "Authorization: Bearer ${access_token}")
    
    # Debug: Show what EAs we found
    # echo "DEBUG: EA search response totalCount: $(echo "$response" | jq -r '.totalCount')"
    if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
        ea_found_name=$(echo "$response" | jq -r '.results[0].name')
        ea_found_id=$(echo "$response" | jq -r '.results[0].id')
        # echo "DEBUG: Found EA ID: $ea_found_id with exact name: '$ea_found_name'"
        echo "INFO: Extension Attribute verified to exist."
        return 0
    else
        # echo "DEBUG: EA not found with exact name match. Searching for partial matches..."
        # Try a broader search to see what EAs exist with similar names
        # response_broad=$(curl --silent --request GET \
        #     --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes?page=0&page-size=200" \
        #     --header "Authorization: Bearer ${access_token}")
        # echo "DEBUG: All EAs containing 'JSC iOS':"
        # echo "$response_broad" | jq -r '.results[] | select(.name | contains("JSC iOS")) | .name'
        
        echo "WARNING: Extension Attribute not found. Waiting additional time..."
        sleep 3
        # Try one more time
        response=$(curl --silent --request GET \
            --url "${jamf_pro_url}/api/v1/mobile-device-extension-attributes?page=0&page-size=200&filter=name%3D%3D%22${encoded_ea_name}%22" \
            --header "Authorization: Bearer ${access_token}")
        if [[ $(echo "$response" | jq -r '.totalCount') -gt 0 ]]; then
            echo "INFO: Extension Attribute verified to exist after retry."
            return 0
        else
            echo "ERROR: Extension Attribute still not found after retry."
            return 1
        fi
    fi
}
######################################################################################################## END FUNCTIONS ################################################################################

################################################################################ MAIN SCRIPT EXECUTION ################################################################################
install_swift_dialog
#check if logo exists, if not download it
if [[ -f "/tmp/UEM_SFB_logo.png" ]]; then
    echo "INFO: App icon file already exists locally, no download needed."
else
    echo "INFO: App icon file not found, downloading..."
    downloadLogo
    exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "ERROR: Failed to download app icon file. Exiting."
        exit 1
    fi  
    echo "SUCCESS: App icon downloaded to $local_icon"
fi

access_token="" # Initialize to empty to ensure a token is fetched on first check
token_expiration_epoch="0" # Initialize to 0 to ensure a token is fetched on first check
checkTokenExpiration

echo "INFO ############ Starting Swift Dialog ############"
if [[ $jamf_pro_url == "" || $client_id == "" || $client_secret == "" ]]; then
    credentialPrompt
else
    echo "INFO: Using Jamf Pro credentials from environment variables."
fi

select_macOS_TPPs_prompt
select_iOS_TPPs_prompt
echo ""
echo "INFO: Processing Computer Extension Attributes and Groups..."
echo "#################################################################################"

# Check token expiration before starting computer processing
checkTokenExpiration



for policy in "${selectedTPPsMac[@]}"; do
    # Check token expiration before each policy processing
    checkTokenExpiration
    
    ea_name="JSC macOS Threat-Prevention-Policy: $policy"
    # check if EA already exists
    check_computer_ea_exists
    if [[ $? -eq 1 ]]; then # If EA exists, skip and check smart group
        group_name="JSC Threat-Prevention-Policy: $policy"
        echo "INFO: Looking for Computer Smart Group named: $group_name"
        get_computer_group_info
        existstatus=$?
        if [[ $existstatus -eq 1 ]]; then # If group exists, skip creation
            continue
        fi
        # Create a smart group for the EA if it doesn't exist
        echo "INFO: Creating Computer Smart Group for policy: $policy"
        create_computer_smart_group "$policy"
        sleep 0.5
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Smart Group for $policy created successfully." Response code: $http_status
            echo ""
        else
            #echo "DEBUG: Full response: $http_status"
            echo "ERROR: Failed to create Smart Group for $policy. HTTP status code: $http_status"
        fi
        continue
    else # If EA doesn't exist, create it and the smart group
        # Create the EA
        echo "INFO: Creating Computer EA for: $policy"
        create_computer_extension_attribute "$policy"
        sleep 0.5 # Wait for 0.5 seconds to avoid hitting rate limits
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Extension Attribute for $policy created successfully." Response code: $http_status
        else
            echo "ERROR: API call failed with HTTP status code: $http_status"
        fi
        # Create a smart group for the EA
        echo "INFO: Creating Computer Smart Group for policy: $policy"
        create_computer_smart_group "$policy"
        sleep 0.5
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Smart Group for $policy created successfully." Response code: $http_status
        else
            #echo "DEBUG: Full response: $http_status"
            echo "ERROR: Failed to create Smart Group for $policy. HTTP status code: $http_status"
        fi
    fi 
done
echo "INFO: Finished creating Extension Attributes and Smart Groups for macOS Threat Prevention Policies."
echo "--------------------------------------------------------------------------------"
echo ""




echo "INFO: Processing Mobile Device Extension Attributes and Groups..."
echo "#################################################################################"

# Check token expiration before starting iOS processing (critical for "Select All" scenarios)
checkTokenExpiration
for policy in "${selectedTPPsiOS[@]}"; do
    # Check token expiration before each policy processing (especially important for later iOS items)
    checkTokenExpiration
    
    ea_name="JSC iOS Threat-Prevention-Policy: $policy"
    # check if EA already exists
    check_mobile_device_ea_exists
    if [[ $? -eq 1 ]]; then # If EA exists, skip and check smart group
        group_name="JSC Threat-Prevention-Policy: $policy"
        echo "INFO: Looking for Mobile Device Smart Group named: $group_name"
        get_mobile_device_group_info
        existstatus=$?
        if [[ $existstatus -eq 1 ]]; then # If group exists, skip creation
            continue
        fi
        # Create a smart group for the EA if it doesn't exist
        echo "INFO: Creating Mobile Device Smart Group for policy: $policy"
        create_mobile_device_smart_group "$policy"
        sleep 0.5
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Smart Mobile Device Group for $policy created successfully. Response code: $http_status"
            echo ""
        else
            echo "ERROR: Failed to create Smart Mobile Device Group for $policy. HTTP status code: $http_status"
        fi
        continue
    else
    # Create the EA
        echo "INFO: Creating Mobile Device EA for policy: $policy"
        create_mobile_device_extension_attribute "$policy" 
        sleep 0.5 # Wait for 0.5 seconds to avoid hitting rate limits
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Mobile Device Extension Attribute for $policy created successfully." Response code: $http_status
            echo ""
        else
            echo "ERROR: API call failed with HTTP status code: $http_status"
        fi
        # Wait and verify EA exists before creating smart group
        echo "INFO: Waiting for Extension Attribute to be available in system..."
        sleep 2
        # Verify EA exists before creating smart group
        verify_mobile_device_ea_exists "$policy"
        if [[ $? -eq 0 ]]; then
            # Create a smart group for the EA
            echo "INFO: Creating Mobile Device Group for policy: $policy"
            # echo "DEBUG: About to create smart group referencing EA: 'JSC iOS Threat-Prevention-Policy: $policy'"
            create_mobile_device_smart_group "$policy"
            sleep 0.5
        else
            echo "ERROR: Skipping Smart Group creation due to EA not being available."
            continue
        fi
        if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
            echo "SUCCESS: Smart Mobile Device Group for $policy created successfully. Response code: $http_status"
            echo ""
        else
            echo "ERROR: Failed to create Smart Mobile Device Group for $policy. HTTP status code: $http_status"
        fi
    fi
done
echo "INFO: Finished creating Extension Attributes and Smart Groups for iOS Threat Prevention Policies."
echo "#################################################################################"

donePrompt




invalidateToken
################################################################################ END MAIN SCRIPT EXECUTION ################################################################################

    