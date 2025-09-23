#!/bin/zsh --no-rcs

# This script creates Extension Attributes and Smart Groups in Jamf Pro for use with Jamf Security Cloud UEM signaling.
# It uses Swift Dialog to present a user interface for selecting which EAs and groups to create.
# The script requires Jamf Pro API credentials:
# - JAMF_PRO_URL: The base URL of your Jamf Pro instance (e.g., https://yourdomain.jamfcloud.com)
# - JAMF_CLIENT_ID_FULL_ADMIN: The client ID of a Jamf Pro API user
# - JAMF_CLIENT_SECRET_FULL_ADMIN: The client secret of a Jamf Pro API user
## Required Permissions:
# - Computer Extension Attributes: Create
# - Mobile Device Extension Attributes: Create
# - Computer Groups: Create
# - Mobile Device Groups: Create

################################################################################
##### CONFIGURABLE VARIABLES #####



jamf_pro_url="${JAMF_PRO_URL}" # Set JAMF_PRO_URL in your environment
client_id="${JAMF_CLIENT_ID}"  # Set JAMF_CLIENT_ID in your environment
client_secret="${JAMF_CLIENT_SECRET}" # Set JAMF_CLIENT_SECRET in your environment
threat_prevention_policies_macOS=("Phishing" "Malware network traffic" "Cryptojacking" "Spam" "Third-party app store traffic" "Vulnerable app installed" "Vulnerable OS (major)" "App inactivity" "Vulnerable OS (minor)"  "Out-of-date OS" "User password disabled")
threat_prevention_policies_iOS=( "Phishing" "Data Leaks" "Malware network traffic" "Cryptojacking" "Spam" "Third-party app store traffic" "Malware" "Sideloaded app installed" "Vulnerable app installed" "Dangerous certificate" "Adversary-in-the-Middle" "Risky hotspots" "Jailbreak" "Vulnerabor OS (major)" "App inactivity" "Lock screen disabled" "Risky iOS Profile" "Vulnerable OS (minor)" "Out-of-date OS")
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
    if [[ token_expiration_epoch -ge current_epoch ]]
    then
        echo "INFO: Token valid until the following epoch time: " "$token_expiration_epoch"
    else
        echo "INFO: No valid token available, getting new token"
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
    selectedTPPsMac=$(dialog \
        --title "JCS UEM Signaling Framework Builder" \
        --message "Please select the Computer Extension Attributes you want to create:" \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --icon "$local_icon" \
        --checkboxstyle "switch,large" \
        --width 800 \
        --infobuttontext "Select All" \
        --button2 "Cancel" \
        --checkbox "${threat_prevention_policies_macOS[0]}" \
        --checkbox "${threat_prevention_policies_macOS[1]}" \
        --checkbox "${threat_prevention_policies_macOS[2]}" \
        --checkbox "${threat_prevention_policies_macOS[3]}" \
        --checkbox "${threat_prevention_policies_macOS[4]}" \
        --checkbox "${threat_prevention_policies_macOS[5]}" \
        --checkbox "${threat_prevention_policies_macOS[6]}" \
        --checkbox "${threat_prevention_policies_macOS[7]}" \
        --checkbox "${threat_prevention_policies_macOS[8]}" \
        --checkbox "${threat_prevention_policies_macOS[9]}" \
        --checkbox "${threat_prevention_policies_macOS[10]}" \
        )
    local exit_code=$?
    if [[ $exit_code -eq 2 ]]; then
        echo "INFO: User cancelled the operation. Exiting."
        exit 0
    elif [[ $exit_code -eq 3 ]]; then
        echo "INFO: User selected 'Select All'. Selecting all Threat Prevention Policies."
        selectedTPPsMac=("${threat_prevention_policies_macOS[@]}")
        echo "INFO: All TPPs selected: ${selectedTPPsMac[@]}"
    else
        selectedTPPsMac=( $(echo "$selectedTPPsMac" | grep ':[[:space:]]*"true"' | cut -d '"' -f 2) )
        echo "INFO: User selected the following TPPs: ${selectedTPPsMac[@]}"
    fi
}

select_iOS_TPPs_prompt() {
    # Prompt user to select an EA
    # when selecting all, all EAs checkboxes should be selected
    echo "###### SWIFT DIALOG PROMPT FOR iOS TPPs ######"
    selectedTPPsiOS=$(dialog \
        --title "JCS UEM Signaling Framework Builder" \
        --message "Please select the Mobile Device Extension Attributes you want to create:" \
        --messagefont "$messageFont" \
        --titlefont "$titleFont" \
        --icon "$local_icon" \
        --checkboxstyle "switch,large" \
        --width 800 \
        --button2 "Cancel" \
        --infobuttontext "Select All" \
        --checkbox "${threat_prevention_policies_iOS[0]}" \
        --checkbox "${threat_prevention_policies_iOS[1]}" \
        --checkbox "${threat_prevention_policies_iOS[2]}" \
        --checkbox "${threat_prevention_policies_iOS[3]}" \
        --checkbox "${threat_prevention_policies_iOS[4]}" \
        --checkbox "${threat_prevention_policies_iOS[5]}" \
        --checkbox "${threat_prevention_policies_iOS[6]}" \
        --checkbox "${threat_prevention_policies_iOS[7]}" \
        --checkbox "${threat_prevention_policies_iOS[8]}" \
        --checkbox "${threat_prevention_policies_iOS[9]}" \
        --checkbox "${threat_prevention_policies_iOS[10]}" \
        --checkbox "${threat_prevention_policies_iOS[11]}" \
        --checkbox "${threat_prevention_policies_iOS[12]}" \
        --checkbox "${threat_prevention_policies_iOS[13]}" \
        --checkbox "${threat_prevention_policies_iOS[14]}" \
        --checkbox "${threat_prevention_policies_iOS[15]}" \
        --checkbox "${threat_prevention_policies_iOS[16]}" \
        --checkbox "${threat_prevention_policies_iOS[17]}" \
        --checkbox "${threat_prevention_policies_iOS[18]}"
        )
        local exit_code=$?
        if [[ $exit_code -eq 2 ]]; then
            echo "INFO: User cancelled the operation. Exiting."
            exit 0
        elif [[ $exit_code -eq 3 ]]; then
            echo "INFO: User selected 'Select All'. Selecting all Threat Prevention Policies."
            selectedTPPsiOS=("${threat_prevention_policies_iOS[@]}")
            echo "INFO: All TPPs selected: ${selectedTPPsiOS[@]}"
            return
        else
            echo "INFO: User selected specific Threat Prevention Policies."
            selectedTPPsiOS=( $(echo "$selectedTPPsiOS" | grep ':[[:space:]]*"true"' | cut -d '"' -f 2) )
            echo "INFO: User selected the following TPPs: ${selectedTPPsiOS[@]}"
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
    \"name\": \"JSC macOS Threat-Prevention_Policy: $policy\",
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
            \"name\": \"JSC Threat-Prevention_Policy: $policy\",
            \"description\": \"Smart Group for devices matching Jamf Security Cloud Threat Prevention Policy: $policy\",
            \"criteria\": [
                {
                    \"name\": \"JSC macOS Threat-Prevention_Policy: $policy\",
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
            \"name\": \"JSC iOS Threat-Prevention_Policy: $policy\",
            \"description\": \"Jamf Security Cloud Threat Prevention Policy for $policy Events\"
            }")
}
# create smart mobile device groups for EA 
# Using old api: JSSResource/mobiledevicegroups/id/0 which needs to add an xml file to create a smart group
create_mobile_device_smart_group() {
    # Create XML payload for smart group creation
    xml_payload="<?xml version=\"1.0\" encoding=\"UTF-8\"?>
        <mobile_device_group>
            <name>JSC Threat-Prevention_Policy: $policy</name>
            <is_smart>true</is_smart>
            <criteria>
                <criterion>
                    <name>JSC iOS Threat-Prevention_Policy: $policy</name>
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
    # Create the group
    http_status=$(curl --silent -w "%{http_code}" -o /dev/null --request POST \
        --url "$jamf_pro_url/JSSResource/mobiledevicegroups/id/0" \
        --header "Authorization: Bearer $access_token" \
        --header 'accept: application/xml' \
        --header 'content-type: application/xml' \
        --data "$xml_payload")
}
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


######################################################################################################## END FUNCTIONS ################################################################################

################################################################################ MAIN SCRIPT EXECUTION ################################################################################
install_swift_dialog
#check if logo exists, if not download it
if [[ -f "/tmp/UEM_SFB_logo.png" ]]; then
    echo "INFO: Logo file already exists."
else
    echo "INFO: Logo file not found, downloading..."
    downloadLogo
    exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        echo "ERROR: Failed to download logo file. Exiting."
        exit 1
    fi  
    echo "debug: Logo downloaded to $local_icon"
fi

access_token="" # Initialize to empty to ensure a token is fetched on first check
token_expiration_epoch="0" # Initialize to 0 to ensure a token is fetched on first check
checkTokenExpiration

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
for policy in "${selectedTPPsMac[@]}"; do
    # Create the EA
    echo "INFO: Creating Comnputer EA for: $policy"
    create_computer_extension_attribute "$policy" 
    sleep 0.25 # Wait for 0.25 seconds to avoid hitting rate limits
    if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
        echo "SUCCESS: Extension Attribute for $policy created successfully." Response code: $http_status
        echo ""
    else
        echo "ERROR: API call failed with HTTP status code: $http_status"
    fi
    # Create a smart group for the EA
    echo "INFO: Creating Computer Smart Group for policy: $policy"
    create_computer_smart_group "$policy"
    sleep 0.25
    if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
        echo "SUCCESS: Smart Group for $policy created successfully." Response code: $http_status
        echo ""
    else
        #echo "DEBUG: Full response: $http_status"
        echo "ERROR: Failed to create Smart Group for $policy. HTTP status code: $http_status"
    fi
done
echo "INFO: Finished creating Extension Attributes and Smart Groups for macOS Threat Prevention Policies."
echo ""


echo "INFO: Processing Mobile Device Extension Attributes and Groups..."
echo "#################################################################################"
for policy in "${selectedTPPsiOS[@]}"; do
    # Create the EA
    echo "INFO: Creating Mobile Device EA for policy: $policy"
    create_mobile_device_extension_attribute "$policy" 
    sleep 0.25 # Wait for 0.25 seconds to avoid hitting rate limits
    if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
        echo "SUCCESS: Mobile Device Extension Attribute for $policy created successfully." Response code: $http_status
        echo ""
    else
        echo "ERROR: API call failed with HTTP status code: $http_status"
    fi
    # Create a smart group for the EA
    echo "INFO: Creating Mobile Device Group for policy: $policy"
    create_mobile_device_smart_group "$policy"
    sleep 0.25
    if [[ "$http_status" -eq 201 ]]; then # Check if the API call was successful (HTTP 201 means "Created")
        echo "SUCCESS: Smart Mobile Device Group for $policy created successfully." Response code: $http_status
        echo ""
    else
        #echo "DEBUG: Full response: $http_status"
        echo "ERROR: Failed to create Smart Mobile Device Group for $policy. HTTP status code: $http_status"
        
    fi
done
echo "INFO: Finished creating Extension Attributes and Smart Groups for iOS Threat Prevention Policies."
echo "#################################################################################"

donePrompt




invalidateToken
################################################################################ END MAIN SCRIPT EXECUTION ################################################################################

    