# ======================================
# VARIABLES (Both NinjaOne & ManageEngine)
# ======================================

# Set TLS 1.2 for secure communications
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#
# ─── NINJAONE VARIABLES ──────────────────────────────────────────────
#
# Pull these three values from NinjaOne “Secret Custom Fields”:
#   • mescriptNinjaurl  
#   • mescriptNinjacid  
#   • mescriptNinjasec
#
$API_BASE_URL        = Ninja-Property-Get mescriptNinjaurl
$NINJA_CLIENT_ID     = Ninja-Property-Get mescriptNinjacid
$NINJA_CLIENT_SECRET = Ninja-Property-Get mescriptNinjasec
$NINJA_SCOPE         = "monitoring management"

if (
    [string]::IsNullOrEmpty($API_BASE_URL) `
    -or [string]::IsNullOrEmpty($NINJA_CLIENT_ID) `
    -or [string]::IsNullOrEmpty($NINJA_CLIENT_SECRET)
) {
    Write-Error "Missing NinjaOne values. Make sure 'mescriptNinjaurl', 'mescriptNinjacid' and 'mescriptNinjasec' are defined as NinjaOne custom fields."
    exit 1
}

#
# ─── MANAGEENGINE VARIABLES ───────────────────────────────────────────
#
# Pull these three values from NinjaOne “Secret Custom Fields”:
#   • mescriptMECid
#   • mescriptMEsec
#   • mescriptMErefresh
#
$ME_CLIENT_ID     = Ninja-Property-Get mescriptMECid
$ME_CLIENT_SECRET = Ninja-Property-Get mescriptMEsec
$ME_REFRESH_TOKEN = Ninja-Property-Get mescriptMErefresh

# Pull only the Accounts Server URL from a custom field:
#   • mescriptMEActServerURL  (e.g. "https://accounts.zoho.com")
#
$ACCOUNTS_SERVER_URL = Ninja-Property-Get mescriptMEActServerURL

# Leave the ManageEngine “Custom Domain” hard-coded (or set elsewhere),
# since we’re not pulling it from NinjaOne any more:
$CUSTOM_DOMAIN = "https://sdpondemand.manageengine.com"

if (
    [string]::IsNullOrEmpty($ME_CLIENT_ID) `
    -or [string]::IsNullOrEmpty($ME_CLIENT_SECRET) `
    -or [string]::IsNullOrEmpty($ME_REFRESH_TOKEN)
) {
    Write-Error "Missing ManageEngine values. Make sure 'mescriptMECid', 'mescriptMEsec', and 'mescriptMErefresh' are defined as NinjaOne custom fields."
    exit 1
}

# Construct the full endpoint now that CUSTOM_DOMAIN is known:
$ASSET_DETAILS_ENDPOINT = "$CUSTOM_DOMAIN/app/itdesk/api/v3/assets"

#
# ─── TEST ASSET UPDATE VARIABLES ────────────────────────────────────────
#
$addNewAssets      = $false
$TEST_ASSET_ID     = ""
$TEST_NINJA_SERIAL = ""
$testing           = $true   # dry-run = $true, real updates = $false
$MaxAttempts       = 10

# Verify that the asset endpoint is non-empty
if ([string]::IsNullOrEmpty($ASSET_DETAILS_ENDPOINT)) {
    Write-Error "ASSET_DETAILS_ENDPOINT is empty. Please verify your ManageEngine custom domain."
    exit 1
}


#
# ======================================
# INITIAL SETUP & LOGGING
# ======================================
#

if (!(Test-Path -Path "C:\admin")) {
    New-Item -ItemType Directory -Path "C:\admin" | Out-Null
}
Start-Transcript -Path "C:\admin\asset_update_log.txt"

# Load ActiveDirectory if available
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Warning "ActiveDirectory module not available. AD lookups may be limited."
} else {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module imported successfully."
}

#########################################
# SECTION 1: NINJAONE SIDE FUNCTIONS
#########################################

function Get-AccessToken_Ninja {
    try {
        $uri = "$API_BASE_URL/oauth/token"
        $headers = @{
            "accept"       = "application/json"
            "Content-Type" = "application/x-www-form-urlencoded"
        }
        $body = "grant_type=client_credentials&client_id=$NINJA_CLIENT_ID&client_secret=$NINJA_CLIENT_SECRET&scope=$NINJA_SCOPE"
        $response = Invoke-WebRequest -Uri $uri -Method Post -Headers $headers -Body $body -UseBasicParsing
        $content = $response.Content | ConvertFrom-Json
        if ($content.access_token) {
            Write-Host "NinjaOne access token retrieved."
            return $content.access_token
        } else {
            Write-Host "Access token not found in response."
            return $null
        }
    } catch {
        Write-Error "Failed to retrieve NinjaOne access token: $($_.Exception.Message)"
        throw "Unable to retrieve NinjaOne access token."
    }
}

function Get-ComputerSystems {
    $headers = @{
        "accept"       = "application/json"
        "Authorization" = "Bearer $global:accessToken_Ninja"
    }
    $csUrl = "$API_BASE_URL/v2/queries/computer-systems"
    try {
        $response = Invoke-RestMethod -Uri $csUrl -Method Get -Headers $headers
        return $response.results
    } catch {
        Write-Error "Failed to retrieve computer systems: $($_.Exception.Message)"
        return $null
    }
}

function Get-LastLoggedOnUser {
    param(
        [Parameter(Mandatory=$true)][int]$DeviceId
    )
    $url = "$API_BASE_URL/v2/device/$DeviceId/last-logged-on-user"
    $headers = @{
        "accept"       = "application/json"
        "Authorization" = "Bearer $global:accessToken_Ninja"
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        return $response
    } catch {
        Write-Error "Failed to retrieve last logged on user for device ID ${DeviceId}: $($_.Exception.Message)"
        return $null
    }
}

function Get-UserDetailsFromAD {
    param(
        [Parameter(Mandatory=$true)][string]$Username
    )
    try {
        if ($Username -match "\\") {
            $sam = $Username.Split("\")[-1]
        } else {
            $sam = $Username
        }
        if ($sam.ToLower().EndsWith(".admin")) {
            Write-Host "Skipping AD lookup for admin account: $Username"
            return $null
        }
        $user = Get-ADUser -Identity $sam -Properties GivenName, Surname, Department -ErrorAction Stop
        if ($user) {
            return @{
                FirstName  = $user.GivenName
                LastName   = $user.Surname
                Department = $user.Department
            }
        } else {
            Write-Host "Failed to retrieve AD details for $Username."
            return $null
        }
    } catch {
        Write-Error "Error during AD lookup for ${Username}: $($_.Exception.Message)"
        return $null
    }
}

function Get-ValidSerialNumber {
    param(
        [Parameter(Mandatory=$true)]$system
    )
    $serial = $system.serialNumber
    $biosSerial = $system.biosSerialNumber
    function IsValidSerial($s) {
        if ([string]::IsNullOrEmpty($s)) { return $false }
        $sTrim = $s.Trim().ToLower()
        if ($sTrim -eq "default string") { return $false }
        if ($sTrim -eq "none") { return $false }
        if ($sTrim -match "vmware") { return $false }
        if ($sTrim -match "^\d{4}-\d{4}-\d{4}-\d{4}-\d{4}-\d{4}-\d{2}$") { return $false }
        return $true
    }
    if (IsValidSerial $serial) {
        return $serial
    } elseif (IsValidSerial $biosSerial) {
        return $biosSerial
    } else {
        return $null
    }
}

function Get-UsernameFromComputerName {
    param(
        [Parameter(Mandatory=$true)][string]$ComputerName
    )
    if ($ComputerName -match "^(.*?)([-]?((lt)|(omini)|(hmini))$)") {
         return $matches[1].Trim()
    } else {
         return "N/A"
    }
}

# Group systems by valid serial; for duplicates, choose the one with the most recent timestamp.
function Get-NinjaData {
    $global:accessToken_Ninja = Get-AccessToken_Ninja
    $systems = Get-ComputerSystems
    if (-not $systems) {
        Write-Error "No computer systems retrieved from NinjaOne. Exiting."
        Stop-Transcript
        exit 1
    }
    Write-Host "Retrieved $($systems.Count) computer systems from NinjaOne."
    $validSystems = @()
    foreach ($system in $systems) {
        $validSerial = Get-ValidSerialNumber -system $system
        if ($validSerial) {
            $system | Add-Member -NotePropertyName "ValidSerial" -NotePropertyValue $validSerial
            $validSystems += $system
        } else {
            Write-Host "Skipping device with DeviceId: $($system.deviceId) due to invalid serial."
        }
    }
    if ($validSystems.Count -eq 0) {
        Write-Error "No systems with valid serial numbers found."
        Stop-Transcript
        exit 1
    }
    $groupedSystems = $validSystems | Group-Object -Property ValidSerial
    $results = @()
    foreach ($group in $groupedSystems) {
        $selectedSystem = $group.Group | Sort-Object -Property timestamp -Descending | Select-Object -First 1
        $deviceId = $selectedSystem.deviceId
        $computerName = $selectedSystem.name
        $timestamp = $selectedSystem.timestamp
        $lastUserInfo = Get-LastLoggedOnUser -DeviceId $deviceId
        $userName = if ($lastUserInfo -and $lastUserInfo.userName) { $lastUserInfo.userName } else { "N/A" }
        if (($userName -eq "N/A") -or ($userName.ToLower().EndsWith(".admin")) -or (-not $userName.StartsWith("GOPFS\"))) {
            $fallbackUser = Get-UsernameFromComputerName -ComputerName $computerName
            if ($fallbackUser -ne "N/A") {
                Write-Host "Fallback username derived from computer name '$computerName': $fallbackUser"
                $userName = $fallbackUser
            }
        }
        $adInfo = $null
        if ($userName -ne "N/A") {
            $adInfo = Get-UserDetailsFromAD -Username $userName
        }
        $results += [PSCustomObject]@{
            DeviceId         = $deviceId
            ComputerName     = $computerName
            SerialNumber     = $selectedSystem.ValidSerial
            LastLoggedOnUser = $userName
            ADFirstName      = if ($adInfo) { $adInfo.FirstName } else { "N/A" }
            ADLastName       = if ($adInfo) { $adInfo.LastName } else { "N/A" }
            ADDepartment     = if ($adInfo) { $adInfo.Department } else { "N/A" }
            Timestamp        = $timestamp
        }
    }
    return $results
}

#########################################
# SECTION 2: MANAGEENGINE SIDE FUNCTIONS
#########################################

# ----------------------------------------
# 0) Refresh-AccessToken_ME
# ----------------------------------------
function Refresh-AccessToken_ME {
    param(
        [Parameter(Mandatory=$true)][string]$ClientId,
        [Parameter(Mandatory=$true)][string]$ClientSecret,
        [Parameter(Mandatory=$true)][string]$RefreshToken,
        [string]$AccountsServerUrl = "https://accounts.zoho.com"
    )
    $tokenEndpoint = "$AccountsServerUrl/oauth/v2/token"
    $body = @{
        grant_type    = "refresh_token"
        client_id     = $ClientId
        client_secret = $ClientSecret
        refresh_token = $RefreshToken
    }
    $formBody = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([uri]::EscapeDataString($_.Value))" }) -join "&"
    try {
        $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $formBody -ContentType "application/x-www-form-urlencoded"
        Write-Host "ManageEngine access token refreshed successfully."
        return $response.access_token
    } catch {
        Write-Error "ManageEngine token refresh failed: $($_.Exception.Message)"
        return $null
    }
}

# ----------------------------------------
# 1) Find-AssetsByNamePrefix
#    Given a NamePrefix string, return up to 100 ME assets whose “name”
#    starts exactly with that prefix. Returns empty array if none.
#    ADDED: debug output for payload and URL.
# ----------------------------------------
function Find-AssetsByNamePrefix {
    param(
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$AssetApiEndpoint,
        [Parameter(Mandatory=$true)][string]$NamePrefix
    )

    # Build headers
    $headers = @{
        "Accept"        = "application/vnd.manageengine.sdp.v3+json"
        "Authorization" = "Zoho-oauthtoken $AccessToken"
        "Content-Type"  = "application/json"
    }

    # Construct v3-style JSON payload using "values" array + "starts with"
    $searchCriteriaObject = @{
        list_info = @{
            row_count       = 100
            search_criteria = @(
                @{
                    field     = "name"
                    condition = "starts with"
                    values    = @($NamePrefix)
                }
            )
        }
    }
    $jsonPayload = $searchCriteriaObject | ConvertTo-Json -Depth 5

    # DEBUG: print raw JSON payload
    Write-Host "`n[DEBUG] Find-AssetsByNamePrefix raw payload:"
    Write-Host $jsonPayload

    # Use UriBuilder to put that JSON into input_data=<JSON>
    try {
        $uriBuilder = [UriBuilder] $AssetApiEndpoint
        $qs         = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
        $qs["input_data"] = $jsonPayload
        $uriBuilder.Query = $qs.ToString()
        $searchUrl = $uriBuilder.Uri.AbsoluteUri
    } catch {
        Write-Error "Failed to build search URL for Find-AssetsByNamePrefix: $($_.Exception.Message)"
        return @()
    }

    # DEBUG: print constructed search URL
    Write-Host "[DEBUG] Find-AssetsByNamePrefix search URL:"
    Write-Host $searchUrl

    # Call the API
    try {
        $response = Invoke-RestMethod -Uri $searchUrl -Method Get -Headers $headers
        if ($null -eq $response.assets) {
            Write-Host "[DEBUG] Find-AssetsByNamePrefix: No 'assets' field in response or zero results."
            return @()
        }
        Write-Host "[DEBUG] Find-AssetsByNamePrefix: returned $($response.assets.Count) asset(s)."
        return $response.assets
    } catch {
        Write-Error ("Name-search failed for prefix '$NamePrefix': $($_.Exception.Message)")
        return @()
    }
}

# ----------------------------------------
# 2) Get-NextNameFromMatches
#    Given a BaseName string and an array of existing asset objects (each has .name),
#    return the next unique name. Behavior:
#      • If no existing asset’s name (case-insensitive) equals BaseName, return BaseName.
#      • Otherwise, return the first “BaseName-i” where i ≥ 2 is the smallest integer
#        that is not already used. (Case-insensitive match.)
# ----------------------------------------
function Get-NextNameFromMatches {
    param(
        [Parameter(Mandatory=$true)][string]$BaseName,
        [Parameter(Mandatory=$true)][array]$ExistingAssets
    )

    # If there are no existing assets at all, just return the plain base.
    if (-not $ExistingAssets -or $ExistingAssets.Count -eq 0) {
        return $BaseName
    }

    # Lower-case version of the base, and a set of all lower-case existing names
    $lowerBase  = $BaseName.ToLower()
    $lowerNames = $ExistingAssets | ForEach-Object { $_.name.ToLower() }

    # 1) If the exact base (case-insensitive) is not present, return BaseName
    if (-not ($lowerNames -contains $lowerBase)) {
        return $BaseName
    }

    # 2) Otherwise, collect every numeric suffix currently in use (including “1” for the bare BaseName)
    $usedSuffixes = [System.Collections.Generic.HashSet[int]]::new()

    foreach ($nmObj in $ExistingAssets) {
        $nmLower = $nmObj.name.ToLower()

        # If it matches exactly the base (e.g. “astephens-lt”), treat that as suffix “1”
        if ($nmLower -eq $lowerBase) {
            $usedSuffixes.Add(1) | Out-Null
            continue
        }

        # If it matches “BaseName-<digits>” exactly, extract that integer
        if ($nmLower -match "^" + [regex]::Escape($lowerBase) + "-(\d+)$") {
            [int]$suffixNum = [int]$matches[1]
            $usedSuffixes.Add($suffixNum) | Out-Null
        }
    }

    # 3) Now scan i = 2, 3, 4, … until we find the first i not in $usedSuffixes
    $i = 2
    while ($true) {
        if (-not $usedSuffixes.Contains($i)) {
            return "$BaseName-$i"
        }
        $i++
    }

    # (We will always return from inside the loop; we never reach here.)
}



# ----------------------------------------
# 3) Update-AssetNameWithPreferredSuffix
#    Searches for any assets whose “name” starts with DesiredBaseName,
#    removes the one we’re about to rename (so we don’t count ourselves),
#    then hands that filtered list to Get-NextNameFromMatches to pick
#    the smallest missing integer suffix. Finally issues the PUT.
# ----------------------------------------
function Update-AssetNameWithPreferredSuffix {
    param(
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$AssetApiEndpoint,
        [Parameter(Mandatory=$true)][string]$AssetId,
        [Parameter(Mandatory=$true)][string]$DesiredBaseName
    )

    # 3.1) Try to find any existing assets whose name starts with DesiredBaseName
    $existingList = Find-AssetsByNamePrefix `
        -AccessToken      $AccessToken `
        -AssetApiEndpoint $AssetApiEndpoint `
        -NamePrefix       $DesiredBaseName

    # If the search itself failed (API error), treat as “no matches”
    if ($existingList -eq $null) {
        $existingList = @()
    }

    # ─────────────────────────────────────────────────────────────────
    # Remove the very asset we’re about to rename, so it doesn’t count.
    # Otherwise Get-NextNameFromMatches will see the old name as “already taken”
    # and force the next suffix to climb unnecessarily.
    # ----------------------------------------
    $existingList = $existingList | Where-Object { $_.id -ne $AssetId }
    # ─────────────────────────────────────────────────────────────────

    # 3.2) Compute unique name via the “first-missing-integer” logic
    if ($existingList.Count -eq 0) {
        $uniqueName = $DesiredBaseName
    } else {
        $uniqueName = Get-NextNameFromMatches -BaseName $DesiredBaseName -ExistingAssets $existingList
    }

    # 3.3) Issue the actual rename PUT
    $updateUrl     = "$AssetApiEndpoint/$AssetId"
    $assetPayload  = @{ "name" = $uniqueName }
    $updatePayload = @{ "asset" = $assetPayload }
    $input_data    = $updatePayload | ConvertTo-Json -Depth 5
    $data          = @{ "input_data" = $input_data }
    $headers       = @{
        "Accept"        = "application/vnd.manageengine.sdp.v3+json"
        "Authorization" = "Zoho-oauthtoken $AccessToken"
        "Content-Type"  = "application/x-www-form-urlencoded"
    }

    try {
        $response = Invoke-RestMethod -Uri $updateUrl -Method Put -Headers $headers -Body $data
        return $response
    } catch {
        Write-Error ("Asset name update failed: $($_.Exception.Message)")
        return $null
    }
}



# ----------------------------------------
# 4) Find-AssetBySerialNumber
#    Search ManageEngine for a given serial_number value. Returns the API response.
# ----------------------------------------
function Find-AssetBySerialNumber {
    param(
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$AssetApiEndpoint,
        [Parameter(Mandatory=$true)][string]$SerialNumber
    )
    $headers = @{
        "Accept"        = "application/vnd.manageengine.sdp.v3+json"
        "Authorization" = "Zoho-oauthtoken $AccessToken"
        "Content-Type"  = "application/json"
    }
    $searchCriteria = '{"list_info":{"search_criteria":{"field":"serial_number.value","condition":"is","value":"' + $SerialNumber + '"}}}'
    $uriBuilder = New-Object System.UriBuilder($AssetApiEndpoint)
    $qs = [System.Web.HttpUtility]::ParseQueryString($uriBuilder.Query)
    $qs["input_data"] = $searchCriteria
    $uriBuilder.Query = $qs.ToString()
    $searchUrl = $uriBuilder.ToString()

    try {
        $response = Invoke-RestMethod -Uri $searchUrl -Method Get -Headers $headers
        return $response
    } catch {
        Write-Error ("Asset search failed for serial " + $SerialNumber + ": $($_.Exception.Message)")
        return $null
    }
}

# ----------------------------------------
# 5) Get-AssetDetails
#    Given an AssetId, fetch full asset object from ManageEngine.
# ----------------------------------------
function Get-AssetDetails {
    param(
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$AssetDetailsEndpoint,
        [Parameter(Mandatory=$true)][string]$AssetId
    )
    $url = "$AssetDetailsEndpoint/$AssetId"
    $headers = @{
        "Accept"        = "application/vnd.manageengine.sdp.v3+json"
        "Authorization" = "Zoho-oauthtoken $AccessToken"
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Method Get -Headers $headers
        return $response.asset
    } catch {
        Write-Error ("Failed to retrieve full details for asset ID ${AssetId}: $($_.Exception.Message)")
        return $null
    }
}

# ----------------------------------------
# 6) Evaluate-AssetForUpdate
#    Compare an ME asset object against the NinjaOne data. Returns an array
#    of PSCustomObjects describing which fields (“ComputerName”, “State”,
#    “User”, “Department”) need updating.
# ----------------------------------------
function Evaluate-AssetForUpdate {
    param(
        [Parameter(Mandatory=$true)][object]$Asset,         # ME asset object
        [Parameter(Mandatory=$true)][object]$NinjaData      # Corresponding NinjaOne data
    )
    $updates = @()

    # 6.1) Compare computer name
    if ($Asset.name -ne $NinjaData.ComputerName) {
        Write-Host "Computer name update needed: ME '$($Asset.name)' vs Ninja '$($NinjaData.ComputerName)'"
        $updates += [PSCustomObject]@{
            Field   = "ComputerName"
            Current = $Asset.name
            New     = $NinjaData.ComputerName
        }
    } else {
        Write-Host "Computer names match."
    }

    # 6.2) Check state
    if ($Asset.state -and $Asset.state.name) {
        if ($Asset.state.name -ne "In Use") {
            Write-Host "State update needed: ME state '$($Asset.state.name)' → 'In Use'"
            $updates += [PSCustomObject]@{
                Field   = "State"
                Current = $Asset.state.name
                New     = "In Use"
            }
        } else {
            Write-Host "State is already 'In Use'."
        }
    } else {
        Write-Host "ME asset state missing; updating to 'In Use'."
        $updates += [PSCustomObject]@{
            Field   = "State"
            Current = "(missing)"
            New     = "In Use"
        }
    }

    # 6.3) Compare user field
    $meUser = ""
    if ($Asset.user -and $Asset.user.name) {
        $meUser = $Asset.user.name
    }
    $ninjaADUser = ""
    if ((-not [string]::IsNullOrEmpty($NinjaData.ADFirstName)) -and ($NinjaData.ADFirstName -ne "N/A")) {
        $ninjaADUser = "$($NinjaData.ADFirstName) $($NinjaData.ADLastName)"
    } else {
        $ninjaADUser = $NinjaData.LastLoggedOnUser
    }

    if ([string]::IsNullOrEmpty($meUser)) {
        Write-Host "User field is blank. Will update with '$ninjaADUser'."
        $updates += [PSCustomObject]@{
            Field   = "User"
            Current = "(blank)"
            New     = $ninjaADUser
        }
    } elseif ($meUser -ne $ninjaADUser) {
        Write-Host "User mismatch: ME '$meUser' vs Ninja '$ninjaADUser'."
        $updates += [PSCustomObject]@{
            Field   = "User"
            Current = $meUser
            New     = $ninjaADUser
        }
    } else {
        Write-Host "User field already correct: $meUser."
    }

    # 6.4) Compare department field
    $meDept   = ""
    if ($Asset.department -and $Asset.department.name) {
        $meDept = $Asset.department.name
    }
    $ninjaDept = $NinjaData.ADDepartment
    if ([string]::IsNullOrEmpty($meDept)) {
        Write-Host "Department is blank. Will update with '$ninjaDept'."
        $updates += [PSCustomObject]@{
            Field   = "Department"
            Current = "(blank)"
            New     = $ninjaDept
        }
    } elseif ($meDept -ne $ninjaDept) {
        Write-Host "Department mismatch: ME '$meDept' vs Ninja '$ninjaDept'."
        $updates += [PSCustomObject]@{
            Field   = "Department"
            Current = $meDept
            New     = $ninjaDept
        }
    } else {
        Write-Host "Department already correct: $meDept."
    }

    return $updates
}

# ----------------------------------------
# 7) Update-AssetState
#    Given an AssetId, State, User, and Department, send a PUT to update those fields.
# ----------------------------------------
function Update-AssetState {
    param(
        [Parameter(Mandatory=$true)][string]$AccessToken,
        [Parameter(Mandatory=$true)][string]$AssetApiEndpoint,
        [Parameter(Mandatory=$true)][string]$AssetId,
        [Parameter(Mandatory=$true)][string]$State,
        [Parameter(Mandatory=$true)][string]$UserFullName,
        [Parameter(Mandatory=$true)][string]$Department
    )
    $updateUrl    = "$AssetApiEndpoint/$AssetId"
    $assetPayload = @{
        "state"      = @{ "name" = $State }
        "user"       = @{ "name" = $UserFullName }
        "department" = @{ "name" = $Department }
    }
    $updatePayload = @{ "asset" = $assetPayload }
    $input_data    = $updatePayload | ConvertTo-Json -Depth 5
    $data          = @{ "input_data" = $input_data }
    $headers       = @{
        "Accept"        = "application/vnd.manageengine.sdp.v3+json"
        "Authorization" = "Zoho-oauthtoken $AccessToken"
        "Content-Type"  = "application/x-www-form-urlencoded"
    }

    try {
        $response = Invoke-RestMethod -Uri $updateUrl -Method Put -Headers $headers -Body $data
        return $response
    } catch {
        Write-Error ("Asset state update failed: $($_.Exception.Message)")
        return $null
    }
}


#########################################
# MAIN EXECUTION (cleaned-up logging)
#########################################
# --- NinjaOne Side ---
$ninjaResults = Get-NinjaData
if (-not $ninjaResults) {
    Write-Error "No data retrieved from NinjaOne. Exiting."
    Stop-Transcript
    exit 1
}
Write-Host "=== NinjaOne Results ==="
$ninjaResults |
    Format-Table DeviceId, ComputerName, SerialNumber, LastLoggedOnUser, ADFirstName, ADLastName, ADDepartment, Timestamp -AutoSize

# --- ManageEngine Side ---
$meAccessToken = Refresh-AccessToken_ME `
    -ClientId         $ME_CLIENT_ID `
    -ClientSecret     $ME_CLIENT_SECRET `
    -RefreshToken     $ME_REFRESH_TOKEN `
    -AccountsServerUrl $ACCOUNTS_SERVER_URL

if (-not $meAccessToken) {
    Write-Error "Failed to get ManageEngine access token. Exiting."
    Stop-Transcript
    exit 1
}
Write-Host "ManageEngine access token: $meAccessToken"

# --- TEST ASSET UPDATE OVERRIDE (if you want to force‐update one specific asset) ---
if (-not [string]::IsNullOrEmpty($TEST_ASSET_ID)) {
    Write-Host "Test asset ID provided: $TEST_ASSET_ID. Forcing update on this asset."

    $meTestAsset = Get-AssetDetails `
        -AccessToken          $meAccessToken `
        -AssetDetailsEndpoint $ASSET_DETAILS_ENDPOINT `
        -AssetId              $TEST_ASSET_ID

    if ($meTestAsset) {
        if (-not [string]::IsNullOrEmpty($TEST_NINJA_SERIAL)) {
            $testNinjaAsset = $ninjaResults |
                Where-Object { $_.SerialNumber -eq $TEST_NINJA_SERIAL } |
                Select-Object -First 1
        }
        if (-not $testNinjaAsset) {
            $testNinjaAsset = $ninjaResults | Select-Object -First 1
        }

        Write-Host "For test asset, using Ninja data:" -ForegroundColor Cyan
        Write-Host "  Computer Name: $($testNinjaAsset.ComputerName)"
        Write-Host "  Serial Number: $($testNinjaAsset.SerialNumber)"
        Write-Host "  User: $($testNinjaAsset.LastLoggedOnUser) / $($testNinjaAsset.ADFirstName) $($testNinjaAsset.ADLastName)"
        Write-Host "  Department: $($testNinjaAsset.ADDepartment)"

        $updates = Evaluate-AssetForUpdate -Asset $meTestAsset -NinjaData $testNinjaAsset

        if ($updates.Count -gt 0) {
            Write-Host "For test asset ID $TEST_ASSET_ID, the following updates are determined:" -ForegroundColor Cyan
            foreach ($update in $updates) {
                Write-Host "  Field: $($update.Field) | ME: $($update.Current) | New: $($update.New)"
            }

            # Split updates into state/user/department and computer name.
            $newState        = ""
            $newUser         = ""
            $newDepartment   = ""
            $newComputerName = ""

            foreach ($upd in $updates) {
                switch ($upd.Field) {
                    "State"        { $newState        = $upd.New }
                    "User"         { $newUser         = $upd.New }
                    "Department"   { $newDepartment   = $upd.New }
                    "ComputerName" { $newComputerName = $upd.New }
                }
            }

            # --- STEP 1: Update state/user/department if needed ---
            if (
                (-not [string]::IsNullOrEmpty($newState)) `
                -or (-not [string]::IsNullOrEmpty($newDepartment))
            ) {
                Write-Host "Updating asset state (and required fields) for asset ID $TEST_ASSET_ID..."

                # If $newUser is empty, fall back to whatever is already in ME ($meTestAsset.user.name)
                $userToSend = if (-not [string]::IsNullOrEmpty($newUser)) {
                    $newUser
                } elseif ($meTestAsset.user -and $meTestAsset.user.name) {
                    $meTestAsset.user.name
                } else {
                    ""
                }

                $stateResponse = Update-AssetState `
                    -AccessToken      $meAccessToken `
                    -AssetApiEndpoint $ASSET_DETAILS_ENDPOINT `
                    -AssetId          $TEST_ASSET_ID `
                    -State            "In Use" `
                    -UserFullName     $userToSend `
                    -Department       $newDepartment

                if ($stateResponse) {
                    Write-Host "State/User/Department updated successfully for asset $TEST_ASSET_ID."
                } else {
                    Write-Host "State/User/Department update failed for asset $TEST_ASSET_ID." -ForegroundColor Red
                }
            }

            # --- STEP 2: Update asset name if needed ---
            if (-not [string]::IsNullOrEmpty($newComputerName)) {
                Write-Host "Updating asset name for asset ID $TEST_ASSET_ID..."

                $nameResponse = Update-AssetNameWithPreferredSuffix `
                    -AccessToken      $meAccessToken `
                    -AssetApiEndpoint $ASSET_DETAILS_ENDPOINT `
                    -AssetId          $TEST_ASSET_ID `
                    -DesiredBaseName  $newComputerName

                if ($nameResponse) {
                    Write-Host "Name updated successfully for asset $TEST_ASSET_ID."
                } else {
                    Write-Host "Name update failed for asset $TEST_ASSET_ID." -ForegroundColor Red
                }
            }
        }
        else {
            Write-Host "Test asset ID $TEST_ASSET_ID is already up-to-date."
        }
    }
    else {
        Write-Host "Failed to retrieve test asset details for ID $TEST_ASSET_ID."
    }
}

# --- Process Each NinjaOne Asset (real loop) ---
foreach ($ninjaAsset in $ninjaResults) {
    $serial = $ninjaAsset.SerialNumber
    Write-Host "-------------------------------------------"
    Write-Host "Ninja node: $($ninjaAsset.DeviceId), Ninja asset name: $($ninjaAsset.ComputerName), Ninja serial number: $serial"
    Write-Host "Checking ManageEngine for serial: $serial"

    $searchResponse = Find-AssetBySerialNumber `
        -AccessToken      $meAccessToken `
        -AssetApiEndpoint $ASSET_DETAILS_ENDPOINT `
        -SerialNumber     $serial

    if ($searchResponse -and $searchResponse.assets -and $searchResponse.assets.Count -gt 0) {
        $meAsset = Get-AssetDetails `
            -AccessToken          $meAccessToken `
            -AssetDetailsEndpoint $ASSET_DETAILS_ENDPOINT `
            -AssetId              $searchResponse.assets[0].id

        if (-not $meAsset) {
            Write-Host "Unable to retrieve full details for ME asset with serial $serial. Skipping."
            continue
        }

        Write-Host "Matched with ME asset ID: $($meAsset.id)"
        $updates = Evaluate-AssetForUpdate -Asset $meAsset -NinjaData $ninjaAsset

        if ($updates.Count -gt 0) {
            if ($testing) {
                Write-Host "Testing mode ON: Would update asset ID $($meAsset.id) with the following updates (Ninja field wins):" -ForegroundColor Cyan
                foreach ($update in $updates) {
                    Write-Host "  Field: $($update.Field) | ME: $($update.Current) | New: $($update.New)"
                }
            }
            else {
                $newState        = ""
                $newUser         = ""
                $newDepartment   = ""
                $newComputerName = ""

                foreach ($upd in $updates) {
                    switch ($upd.Field) {
                        "State"        { $newState        = $upd.New }
                        "User"         { $newUser         = $upd.New }
                        "Department"   { $newDepartment   = $upd.New }
                        "ComputerName" { $newComputerName = $upd.New }
                    }
                }

                # If any of State/Department changed, update those first:
                if (
                    (-not [string]::IsNullOrEmpty($newState)) `
                    -or (-not [string]::IsNullOrEmpty($newDepartment))
                ) {
                    # If newUser is empty, fall back to the existing ME user:
                    $userToSend = if (-not [string]::IsNullOrEmpty($newUser)) {
                        $newUser
                    } elseif ($meAsset.user -and $meAsset.user.name) {
                        $meAsset.user.name
                    } else {
                        ""
                    }

                    $updateResponse = Update-AssetState `
                        -AccessToken      $meAccessToken `
                        -AssetApiEndpoint $ASSET_DETAILS_ENDPOINT `
                        -AssetId          $meAsset.id `
                        -State            "In Use" `
                        -UserFullName     $userToSend `
                        -Department       $newDepartment

                    if ($updateResponse) {
                        Write-Host "State/User/Department updated successfully for asset $($meAsset.id)."
                    } else {
                        Write-Host "State/User/Department update failed for asset $($meAsset.id)." -ForegroundColor Red
                    }
                }

                # Now, if ComputerName needs updating, call the preferred‐suffix function:
                if (-not [string]::IsNullOrEmpty($newComputerName)) {
                    $updateResponse2 = Update-AssetNameWithPreferredSuffix `
                        -AccessToken      $meAccessToken `
                        -AssetApiEndpoint $ASSET_DETAILS_ENDPOINT `
                        -AssetId          $meAsset.id `
                        -DesiredBaseName  $newComputerName

                    if ($updateResponse2) {
                        Write-Host "Name updated successfully for asset $($meAsset.id)."
                    } else {
                        Write-Host "Name update failed for asset $($meAsset.id)." -ForegroundColor Red
                    }
                }
            }
        }
        else {
            Write-Host "Asset ID $($meAsset.id) is already up-to-date. Skipping update."
        }
    }
    else {
        Write-Host "No asset found in ManageEngine for serial '$serial'."
        # Since $addNewAssets is $false, we do not add new assets.
    }
}

Write-Host "ManageEngine processing complete. (Practice mode: $testing)"
Stop-Transcript
