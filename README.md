# **NinjaOne to ManageEngine Asset Sync**

This PowerShell script synchronizes asset information from **NinjaOne** to **ManageEngine ServiceDesk Plus Cloud**. It is designed to be run on a scheduled basis from a secure machine within your NinjaOne environment.

The script uses the asset's **serial number** as the unique identifier to match devices between the two platforms. For each matching device, it updates the following fields in ManageEngine to reflect the data from NinjaOne and Active Directory:

- **Asset Name:** Updated to match the NinjaOne device name. The script intelligently handles duplicate names by appending a suffix (e.g., hostname-2, hostname-3).
- **Asset State:** Set to "In Use".
- **User:** Assigned based on the last logged-on user from NinjaOne, enriched with the full name from Active Directory if available.
- **Department:** Updated based on the user's department information from Active Directory.

## **Prerequisites: The Secure Script Runner**

For security, it is critical to run this script from a dedicated and isolated machine. This machine will have access to API credentials with high-level permissions.

1. **Select a Dedicated Machine**: Use a dedicated machine for running scripts that will not be used for other tasks. A Windows Server Core VM is a great choice. This machine should only be accessible to System Administrator accounts.
2. **Create a "Scripting" Organization**: In NinjaOne, create a new organization (e.g., "Internal Scripting") to house the dedicated script runner machine. This isolates it from your client organizations.
3. **Create a Custom Role**:
    - Navigate to **Administration** > **Devices** > **Roles**.
    - Scroll to the **Windows Server** section, click the ellipsis (...), and select **Add** to create a new role named "Script Runner Role".
4. **Secure Technician Permissions**: Update your technician roles to ensure only System Administrators have access to the new "Scripting" organization and the "Script Runner Role".
5. **Assign the Machine**: Install the NinjaOne agent on your dedicated machine and move it into the new "Scripting" organization. Edit the device and assign it the "Script Runner Role".

## **How to Set Up**

### **Part 1: Configure ManageEngine ServiceDesk Plus**

First, you need to create an OAuth 2.0 client in the Zoho Developer Console to allow the script to access the ManageEngine API.

1. **Log in to the Zoho Developer Console** for your data center:
    - US: <https://api-console.zoho.com/>
    - EU: <https://api-console.zoho.eu/>
    - Other data centers are also available.
2. Click **Add Client** and choose **Self Client**. This type is used for server-to-server integrations without user interaction.
3. Click **Create**. Acknowledge the warning and you will be presented with your new Client ID and Client Secret.
4. Navigate to the **Generate Code** tab.
    - Enter the following scopes, separated by a comma:  
        SDPOnDemand.assets.READ,SDPOnDemand.assets.WRITE
    - Set a short duration (e.g., 10 minutes).
    - Provide a **Scope Description** for your own records.
    - Click **Create**.
5. A pop-up will appear with a **Code**. This is a temporary code used only once to generate your first **Refresh Token**. Copy this code immediately.
6. **Generate the Refresh Token**: The temporary code must be exchanged for a permanent refresh token. A separate PowerShell script is provided for this one-time task.
    - Run the Get-MERefreshToken.ps1 script (provided in a separate file).
    - When prompted, enter your **Client ID**, **Client Secret**, the temporary **Code** you just generated, and your accounts server URL (e.g., <https://accounts.zoho.com>).
    - The script will output a **Refresh Token**. **Securely save this token**. You will need it in the next section.

### **Part 2: Create API Credentials in NinjaOne**

Next, create a new API client in NinjaOne for the script to use for its own operations.

1. In NinjaOne, navigate to **Administration** > **Apps** > **API**.
2. Click **\+ Add client app** and create a new credential.
3. Grant it the **Monitoring** and **Management** scopes.
4. Securely save the **Client ID** and **Client Secret** for the next steps.

### **Part 3: Create Role Custom Fields for Credentials**

The script requires API details for both NinjaOne and ManageEngine to be stored in secure custom fields. These must be **Role Custom Fields** assigned only to your "Script Runner Role" to maintain security.

1. Navigate to **Administration** > **Devices** > **Roles**.
2. Select the **Script Runner Role** you created.
3. Go to the **Device Custom Fields** tab.
4. Click **Add a Field** and create the following seven fields.
    - **Important**: The Name must match exactly, as the script uses it directly. The Label is the friendly display name you will see in the UI.

| **Label (Display Name)** | **Name (Internal)** | **Type** | **Permissions** | **Description** |
| --- | --- | --- | --- | --- |
| ME Script - Ninja URL | mescriptNinjaurl | Text | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | Your NinjaOne API base URL (e.g., <https://app.ninjarmm.com/v2>) |
| --- | --- | --- | --- | --- |
| ME Script - Ninja Client ID | mescriptNinjacid | Secure | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The NinjaOne API Client ID from Part 2. |
| --- | --- | --- | --- | --- |
| ME Script - Ninja Secret | mescriptNinjasec | Secure | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The NinjaOne API Client Secret from Part 2. |
| --- | --- | --- | --- | --- |
| ME Script - ME Client ID | mescriptMECid | Secure | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The ManageEngine Client ID from Part 1. |
| --- | --- | --- | --- | --- |
| ME Script - ME Secret | mescriptMEsec | Secure | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The ManageEngine Client Secret from Part 1. |
| --- | --- | --- | --- | --- |
| ME Script - ME Refresh Token | mescriptMErefresh | Secure | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The permanent ManageEngine Refresh Token from Part 1. |
| --- | --- | --- | --- | --- |
| ME Script - ME Accts URL | mescriptMEActServerURL | Text | Technician: Editable&lt;br&gt;Automations: Read Only&lt;br&gt;API: None | The Zoho Accounts Server URL (e.g., <https://accounts.zoho.com>) |
| --- | --- | --- | --- | --- |

### **Part 4: Populate Credentials on the Script Runner Device**

1. Navigate to the dedicated script runner device within NinjaOne.
2. In the device details, find the **Custom Fields** section.
3. Enter all the corresponding values for the seven fields you just created.

### **Part 5: Configure the Script**

Before running, review the variables in the script to ensure they match your environment.

- $CUSTOM_DOMAIN: Set this to your full ManageEngine ServiceDesk Plus URL (e.g., <https://sdpondemand.manageengine.com>).
- $testing: Set to $true for a dry run that logs what _would_ be changed without making any actual updates. Set to $false for live operation.
- $TEST_ASSET_ID / $TEST_NINJA_SERIAL: These can be used to force the script to only process a single, specific asset for testing purposes. Leave them as empty strings ("") for normal operation.

### **Part 6: Create and Schedule the Script in NinjaOne**

1. Navigate to **Administration** > **Library** > **Automation**.
2. Click **\+ Add** and select **New Script**.
3. Configure the script settings:
    - **Name**: ManageEngine Asset Sync
    - **Description**: Syncs asset data from NinjaOne to ManageEngine ServiceDesk Plus.
    - **Language**: PowerShell
    - **Operating System**: Windows
    - **Architecture**: All
4. Copy the entire content of the script file and paste it into the script editor.
5. Create a new scheduled task or policy to run the script on your dedicated script runner machine.
    - **IMPORTANT**: Set the script to **Run As: System**.
    - **Why?** The script uses Ninja's built-in Ninja-Property-Get command to read the secure custom fields. This command requires SYSTEM privileges to function.

## **Logging**

The script creates a detailed log file of its execution, which is overwritten each time it runs. You can find this log on the script runner machine at: C:\\admin\\asset_update_log.txt.
