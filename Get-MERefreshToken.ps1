# Get-MERefreshToken.ps1
#
# A one-time use script to generate the initial Refresh Token from ManageEngine ServiceDesk Plus Cloud.
#
# Instructions:
# 1. Log in to your Zoho API Console (e.g., https://api-console.zoho.com).
# 2. Create a "Self Client" to get a Client ID and Client Secret.
# 3. Go to the "Generate Code" tab for that client.
# 4. Enter the required scopes: SDPOnDemand.assets.READ,SDPOnDemand.assets.WRITE
# 5. Generate a temporary code (valid for a few minutes).
# 6. Run this script and enter the details when prompted.
# 7. Securely store the resulting Refresh Token.

# Set TLS 1.2 for secure communications
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# --- USER INPUT ---
$clientId = Read-Host "Enter your ManageEngine Client ID"
$clientSecret = Read-Host "Enter your ManageEngine Client Secret"
$code = Read-Host "Enter the temporary Code you just generated"
$accountsUrl = Read-Host "Enter your Zoho Accounts Server URL (e.g., https://accounts.zoho.com)"

if ([string]::IsNullOrEmpty($clientId) -or [string]::IsNullOrEmpty($clientSecret) -or [string]::IsNullOrEmpty($code) -or [string]::IsNullOrEmpty($accountsUrl)) {
    Write-Error "All fields are mandatory. Please run the script again."
    exit 1
}

# --- API CALL ---
$tokenEndpoint = "$accountsUrl/oauth/v2/token"

$body = @{
    grant_type    = "authorization_code"
    client_id     = $clientId
    client_secret = $clientSecret
    code          = $code
}

# The body must be URL-encoded, not sent as a JSON object for this request.
$formBody = ($body.GetEnumerator() | ForEach-Object { "$($_.Key)=$([uri]::EscapeDataString($_.Value))" }) -join "&"

Write-Host "`nRequesting token from $tokenEndpoint..."

try {
    $response = Invoke-RestMethod -Uri $tokenEndpoint -Method Post -Body $formBody -ContentType "application/x-www-form-urlencoded"

    if ($response.refresh_token) {
        Write-Host "SUCCESS!" -ForegroundColor Green
        Write-Host "----------------------------------------------------------------"
        Write-Host "Your Refresh Token is:"
        Write-Host $response.refresh_token -ForegroundColor Yellow
        Write-Host "----------------------------------------------------------------"
        Write-Host "SAVE THIS TOKEN SECURELY. You will add it to a custom field in NinjaOne."

        if ($response.access_token) {
            Write-Host "`nAn Access Token was also generated (expires in 1 hour):"
            Write-Host $response.access_token
        }
    }
    else {
        Write-Error "The response did not contain a refresh_token. Response details:"
        Write-Output ($response | ConvertTo-Json -Depth 5)
    }
}
catch {
    Write-Error "Failed to generate refresh token. The error was:"
    Write-Error $_.Exception.Message
    # Try to get more detailed error info from the response body if it exists
    $errorResponse = $_.Exception.Response.GetResponseStream()
    $streamReader = New-Object System.IO.StreamReader($errorResponse)
    $errorBody = $streamReader.ReadToEnd()
    if (-not [string]::IsNullOrEmpty($errorBody)) {
        Write-Host "Error details from API:"
        Write-Host $errorBody
    }
}
