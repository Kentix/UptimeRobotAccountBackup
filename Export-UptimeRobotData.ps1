<#
.SYNOPSIS
    Exports UptimeRobot account and monitor data to CSV and JSON files.

.DESCRIPTION
    This script retrieves all available account and monitor data from the UptimeRobot API.
    It supports comprehensive logging (with localisation), external configuration,
    batch processing, progress reporting, performance telemetry collection, enhanced error recovery,
    secure API key handling (with encryption support), HTTPS certificate validation, and
    automated documentation generation from comment‑based help.

    Additionally, the script now conditionally includes the custom_uptime_ratios parameter.
    If you pass a non‑empty value via –CustomUptimeRatios, it will be sent; otherwise it will be omitted,
    letting the API use its default. If the API returns an error about custom_uptime_ratios, a detailed
    error message is logged instructing you to ensure each ratio is between 1 and 10000.

.PARAMETER ApiKey
    The UptimeRobot API key in plain text.
    (Not required if –GenerateDocs is specified.)

.PARAMETER SecureApiKey
    A SecureString containing the UptimeRobot API key.
    (Not required if –GenerateDocs is specified.)

.PARAMETER OutputPath
    The directory where output files (CSV, JSON, and log files) will be saved.
    Default: the current working directory.

.PARAMETER LogLevel
    The logging level. Acceptable values: 'Info', 'Warning', 'Error'.
    Default: 'Info'.

.PARAMETER MaxRetries
    The maximum number of retry attempts for API calls on transient failures.
    Acceptable range: 0–10. Default: 3.

.PARAMETER RetryDelaySeconds
    The delay (in seconds) between retry attempts.
    Acceptable range: 1–60. Default: 2 seconds.

.PARAMETER RateLimitDelaySeconds
    The delay (in seconds) after each successful API call for rate limiting.
    Acceptable range: 0–10. Default: 1 second.

.PARAMETER BatchSize
    The number of monitor records to process per batch.
    Default: 50.

.PARAMETER ConfigFile
    An optional path to a JSON configuration file.
    Settings in this file override command‑line parameters.
    Example file content:
    {
        "EncryptedApiKey": "BASE64_ENCRYPTED_API_KEY",
        "OutputPath": "C:\\Exports",
        "LogLevel": "Info",
        "MaxRetries": 3,
        "RetryDelaySeconds": 2,
        "RateLimitDelaySeconds": 1,
        "BatchSize": 50,
        "Culture": "en-US"
    }
    Note: Alternatively, the configuration file may include the plain "ApiKey" field.

.PARAMETER Culture
    The culture code for localised error messages (e.g. "en-US", "fr-FR").
    Default: "en-US".

.PARAMETER EncryptionCertThumbprint
    The thumbprint of the certificate used to decrypt the encrypted API key found in the configuration file.
    This parameter is required if the configuration file contains an "EncryptedApiKey" field.

.PARAMETER GenerateDocs
    If specified, the script will generate documentation from its comment‑based help and then exit.

.PARAMETER CustomUptimeRatios
    A comma‑separated list of day values for uptime ratios. Each value must be between 1 and 10000.
    Default is "1,7,30". If this value is empty, the parameter will be omitted so that the API uses its default.

.EXAMPLE
    .\Export-UptimeRobotData.ps1 -ApiKey "YOUR_API_KEY" -OutputPath "C:\Exports"

.EXAMPLE
    .\Export-UptimeRobotData.ps1 -SecureApiKey (Read-Host -AsSecureString) -ConfigFile ".\config.json" -EncryptionCertThumbprint "AB12CD34EF56..."

.EXAMPLE
    .\Export-UptimeRobotData.ps1 -GenerateDocs -OutputPath "C:\Exports"

.NOTES
    Author: Your Name
    Date: 2025-02-07
#>

[CmdletBinding(DefaultParameterSetName = 'Plain')]
param (
    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [System.Security.SecureString]$SecureApiKey,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Info', 'Warning', 'Error')]
    [string]$LogLevel = 'Info',

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 10)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 60)]
    [int]$RetryDelaySeconds = 2,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0, 10)]
    [int]$RateLimitDelaySeconds = 1,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 500)]
    [int]$BatchSize = 50,

    [Parameter(Mandatory = $false)]
    [string]$ConfigFile,

    [Parameter(Mandatory = $false)]
    [string]$Culture = "en-US",

    [Parameter(Mandatory = $false)]
    [string]$EncryptionCertThumbprint,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateDocs,

    [Parameter(Mandatory = $false)]
    [string]$CustomUptimeRatios = "1,7,30"
)

Set-StrictMode -Version Latest

# --- If not generating docs, require an API key ---
if (-not $GenerateDocs -and -not $ApiKey -and -not $SecureApiKey) {
    Write-Error "Either -ApiKey or -SecureApiKey must be provided unless -GenerateDocs is specified."
    exit 1
}

# Global telemetry for operational insights.
$global:Telemetry = [ordered]@{
    APICallCount         = 0
    TotalAPICallDuration = 0  # in milliseconds
    APICallErrors        = 0
}

# --- External Configuration Processing ---
if ($ConfigFile) {
    if (Test-Path $ConfigFile) {
        try {
            $configData = Get-Content -Path $ConfigFile -Raw | ConvertFrom-Json
            if ($configData.ApiKey) {
                $ApiKey = $configData.ApiKey
                $SecureApiKey = $null  # override secure key if plain key is set
            }
            elseif ($configData.EncryptedApiKey) {
                if ($EncryptionCertThumbprint) {
                    $ApiKey = Decrypt-ApiKey -EncryptedApiKey $configData.EncryptedApiKey -CertThumbprint $EncryptionCertThumbprint
                    $SecureApiKey = $null
                }
                else {
                    Write-Error "EncryptedApiKey found in configuration, but EncryptionCertThumbprint was not provided."
                    exit 1
                }
            }
            if ($configData.OutputPath) { $OutputPath = $configData.OutputPath }
            if ($configData.LogLevel) { $LogLevel = $configData.LogLevel }
            if ($configData.MaxRetries) { $MaxRetries = $configData.MaxRetries }
            if ($configData.RetryDelaySeconds) { $RetryDelaySeconds = $configData.RetryDelaySeconds }
            if ($configData.RateLimitDelaySeconds) { $RateLimitDelaySeconds = $configData.RateLimitDelaySeconds }
            if ($configData.BatchSize) { $BatchSize = $configData.BatchSize }
            if ($configData.Culture) { $Culture = $configData.Culture }
            Write-Host "Configuration loaded from '$ConfigFile'."
        }
        catch {
            Write-Error "Failed to load configuration from file '$ConfigFile': $_"
            exit 1
        }
    }
    else {
        Write-Error "Configuration file '$ConfigFile' not found."
        exit 1
    }
}

# --- Automated Documentation Generation ---
function Generate-Documentation {
    [CmdletBinding()]
    param ()
    try {
        # Use $PSCommandPath which holds the current script file's full path.
        $scriptPath = $PSCommandPath
        if (-not $scriptPath) {
            throw "Script path not found."
        }
        $helpContent = Get-Help $scriptPath -Full | Out-String
        $docFile = Join-Path $OutputPath "Documentation_$(Get-Date -Format 'yyyyMMdd_HHmmss').md"
        $helpContent | Out-File -FilePath $docFile -Encoding UTF8
        Write-Host "Documentation generated at $docFile"
    }
    catch {
        Write-Error "Failed to generate documentation: $_"
    }
}
if ($GenerateDocs) {
    Generate-Documentation
    exit
}

# --- Secure API Key Handling ---
if ($PSCmdlet.ParameterSetName -eq 'Secure') {
    try {
        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureApiKey)
        $PlainApiKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
    catch {
        Write-Error "Failed to convert secure API key to plain text: $_"
        exit 1
    }
}
else {
    $PlainApiKey = $ApiKey
}

# --- Global Settings ---
$script:API_BASE_URL         = "https://api.uptimerobot.com/v2"
$script:LOG_FILE             = Join-Path $OutputPath "log_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:CurrentLogLevel      = $LogLevel
$script:MaxRetries           = $MaxRetries
$script:RetryDelaySeconds    = $RetryDelaySeconds
$script:RateLimitDelaySeconds= $RateLimitDelaySeconds
$script:CurrentCulture       = $Culture

$levels = @{ "Info" = 1; "Warning" = 2; "Error" = 3 }

# --- HTTPS Certificate Validation ---
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $certificate, $chain, $sslPolicyErrors)
    if ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None) {
        return $true
    }
    else {
        Write-Host "HTTPS Certificate validation error: $sslPolicyErrors" -ForegroundColor Red
        return $false
    }
}

# --- Localised Messages Dictionary ---
$LocalizedMessages = @{
    "en-US" = @{
        "ConfigFileNotFound"          = "Configuration file '{0}' not found."
        "ConfigLoadError"             = "Failed to load configuration from file '{0}': {1}"
        "SecureApiKeyConversionError" = "Failed to convert secure API key to plain text: {0}"
        "APICallFailed"               = "API call to '{0}' failed: {1}"
        "ExceededRetries"             = "Exceeded maximum retries ({0}) for API call to '{1}'."
        "ExportFailed"                = "Export failed: {0}"
        "ScriptExecutionFailed"       = "Script execution failed: {0}"
    }
    "fr-FR" = @{
        "ConfigFileNotFound"          = "Fichier de configuration '{0}' introuvable."
        "ConfigLoadError"             = "Échec du chargement de la configuration depuis le fichier '{0}' : {1}"
        "SecureApiKeyConversionError" = "Échec de la conversion de la clé API sécurisée en texte clair : {0}"
        "APICallFailed"               = "L'appel API vers '{0}' a échoué : {1}"
        "ExceededRetries"             = "Nombre maximal de tentatives dépassé ({0}) pour l'appel API vers '{1}'."
        "ExportFailed"                = "L'exportation a échoué : {0}"
        "ScriptExecutionFailed"       = "L'exécution du script a échoué : {0}"
    }
}

function Get-LocalizedMessage {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Key,
        [Parameter(Mandatory = $false)]
        [object[]]$Args
    )
    if (-not $LocalizedMessages.ContainsKey($script:CurrentCulture)) {
        $script:CurrentCulture = "en-US"
    }
    $msgTemplate = $LocalizedMessages[$script:CurrentCulture][$Key]
    if ($Args) {
        return $msgTemplate -f $Args
    }
    return $msgTemplate
}

# --- Write-LogMessage: Logs messages to console and file ---
function Write-LogMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    if ($levels[$Level] -lt $levels[$script:CurrentLogLevel]) { return }
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    switch ($Level) {
        'Warning' { Write-Warning $Message }
        'Error' { Write-Error $Message }
        default { Write-Host $Message }
    }
    $logMessage | Out-File -FilePath $script:LOG_FILE -Append
}

# --- Decrypt-ApiKey: Decrypts an encrypted API key using a certificate ---
function Decrypt-ApiKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedApiKey,
        [Parameter(Mandatory = $true)]
        [string]$CertThumbprint
    )
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "CurrentUser")
        $store.Open("ReadOnly")
        $cert = $store.Certificates | Where-Object { $_.Thumbprint -eq $CertThumbprint }
        if (-not $cert) {
            throw "Certificate with thumbprint '$CertThumbprint' not found."
        }
        $store.Close()
        $rsa = $cert.GetRSAPrivateKey()
        $encryptedBytes = [Convert]::FromBase64String($EncryptedApiKey)
        $decryptedBytes = $rsa.Decrypt($encryptedBytes, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
        $decryptedApiKey = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        return $decryptedApiKey
    }
    catch {
        Write-LogMessage -Level Error -Message "Failed to decrypt API key: $_"
        throw $_
    }
}

# --- Cleanse-Data: Validates and cleans data ---
function Cleanse-Data {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )
    $cleaned = @{}
    foreach ($key in $Data.Keys) {
        $value = $Data[$key]
        if ($null -eq $value) {
            $cleaned[$key] = ""
        }
        elseif ($value -is [string]) {
            $cleaned[$key] = $value.Trim()
        }
        else {
            $cleaned[$key] = $value
        }
    }
    return $cleaned
}

# --- Get-FlattenedObject: Recursively flattens nested objects ---
function Get-FlattenedObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,
        [string]$Prefix = ""
    )
    Write-LogMessage "Entering Get-FlattenedObject. Prefix: '$Prefix'. Object type: $($InputObject.GetType().Name)" "Info"
    $hash = @{}
    foreach ($property in $InputObject.PSObject.Properties) {
        $name = if ($Prefix) { "${Prefix}_$($property.Name)" } else { $property.Name }
        $value = $property.Value
        if ($value -is [PSCustomObject] -or $value -is [hashtable]) {
            Write-LogMessage "Recursing into property '$name'." "Info"
            $nested = Get-FlattenedObject -InputObject $value -Prefix $name
            $hash += $nested
        }
        elseif ($value -is [Array]) {
            for ($i = 0; $i -lt $value.Count; $i++) {
                if ($value[$i] -is [PSCustomObject] -or $value[$i] -is [hashtable]) {
                    Write-LogMessage "Recursing into array element '${name}_$i'." "Info"
                    $nested = Get-FlattenedObject -InputObject $value[$i] -Prefix "${name}_${i}"
                    $hash += $nested
                }
                else {
                    Write-LogMessage "Processing array element '${name}_$i'." "Info"
                    $hash["${name}_${i}"] = $value[$i]
                }
            }
        }
        else {
            Write-LogMessage "Processing property '$name'." "Info"
            $hash[$name] = $value
        }
    }
    Write-LogMessage "Exiting Get-FlattenedObject. Prefix '$Prefix' produced $($hash.Keys.Count) keys." "Info"
    return $hash
}

# --- Get-Batches: Splits an array into batches ---
function Get-Batches {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Items,
        [Parameter(Mandatory = $true)]
        [int]$BatchSize
    )
    $batches = @()
    for ($i = 0; $i -lt $Items.Count; $i += $BatchSize) {
        $end = [math]::Min($i + $BatchSize - 1, $Items.Count - 1)
        $batches += ,($Items[$i..$end])
    }
    return $batches
}

# --- Invoke-UptimeRobotApi: Calls the UptimeRobot API with retries, rate limiting, telemetry, and enhanced error recovery ---
function Invoke-UptimeRobotApi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Parameters
    )
    Write-LogMessage "Entering Invoke-UptimeRobotApi. Endpoint: '$Endpoint'." "Info"
    $attempt = 0
    while ($attempt -le $script:MaxRetries) {
        $attemptStart = Get-Date
        try {
            $uri = "$script:API_BASE_URL/$Endpoint"
            $logParams = $Parameters.Clone()
            $logParams['api_key'] = '***'
            Write-LogMessage "Attempt $($attempt+1): Calling '$uri'. Parameters: $([System.Management.Automation.PSObject]::AsPSObject($logParams) | Out-String)" "Info"
            $Parameters['api_key'] = $PlainApiKey
            $response = Invoke-RestMethod -Uri $uri -Method Post -Body $Parameters -ContentType 'application/x-www-form-urlencoded'
            if ($response.stat -ne 'ok') {
                throw "API returned error: $($response.error.message)"
            }
            $duration = (Get-Date) - $attemptStart
            $global:Telemetry.APICallCount++
            $global:Telemetry.TotalAPICallDuration += $duration.TotalMilliseconds
            Write-LogMessage "Attempt $($attempt+1): API call to '$Endpoint' succeeded in $($duration.TotalMilliseconds) ms." "Info"
            if ($script:RateLimitDelaySeconds -gt 0) {
                Write-LogMessage "Sleeping for $script:RateLimitDelaySeconds seconds (rate limiting)." "Info"
                Start-Sleep -Seconds $script:RateLimitDelaySeconds
            }
            Write-LogMessage "Exiting Invoke-UptimeRobotApi." "Info"
            return $response
        }
        catch {
            $duration = (Get-Date) - $attemptStart
            $global:Telemetry.APICallErrors++
            $errorMsg = $_.Exception.Message
            if ($Endpoint -eq "getMonitors" -and $errorMsg -match "custom_uptime_ratios") {
                Write-LogMessage "API error indicates that the custom_uptime_ratios parameter is invalid.
Please ensure each value is a number between 1 and 10000. Current value: '$($Parameters.custom_uptime_ratios)'.
You can override this value with the -CustomUptimeRatios parameter." "Error"
            }
            else {
                Write-LogMessage "Attempt $($attempt+1): API call to '$Endpoint' failed after $($duration.TotalMilliseconds) ms: $errorMsg" "Error"
            }
            if ($attempt -eq $script:MaxRetries) {
                Write-LogMessage -Level Error -Message (Get-LocalizedMessage "ExceededRetries" @($script:MaxRetries, $Endpoint)) "Error"
                throw
            }
            else {
                Write-LogMessage "Waiting $script:RetryDelaySeconds seconds before retrying." "Info"
                Start-Sleep -Seconds $script:RetryDelaySeconds
            }
        }
        $attempt++
    }
}

# --- Export-UptimeRobotData: Retrieves, validates, cleans, and exports data ---
function Export-UptimeRobotData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OutputPath
    )
    Write-LogMessage "Entering Export-UptimeRobotData. OutputPath: '$OutputPath'" "Info"
    try {
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Validating output directory" -PercentComplete 10
        if (-not (Test-Path $OutputPath)) {
            Write-LogMessage "Output path '$OutputPath' does not exist. Creating directory." "Info"
            New-Item -ItemType Directory -Path $OutputPath | Out-Null
        }
        else {
            Write-LogMessage "Output path '$OutputPath' exists." "Info"
        }
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Retrieving account details" -PercentComplete 30
        Write-LogMessage "Retrieving account details..." "Info"
        $accountResponse = Invoke-UptimeRobotApi -Endpoint "getAccountDetails" -Parameters @{}
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Retrieving monitors" -PercentComplete 50
        Write-LogMessage "Retrieving monitors..." "Info"
        # Build the parameters for getMonitors. Conditionally include custom_uptime_ratios.
        $monitorParams = @{
            logs                  = "1"
            response_times        = "1"
            alert_contacts        = "1"
            all_time_uptime_ratio = "1"
            custom_http_headers   = "1"
            timezone              = "1"
            maintenance_windows   = "1"
            ssl                   = "1"
            mwindows              = "1"
        }
        if ($CustomUptimeRatios -and $CustomUptimeRatios.Trim() -ne "") {
            $monitorParams.custom_uptime_ratios = $CustomUptimeRatios
        }
        $monitorsResponse = Invoke-UptimeRobotApi -Endpoint "getMonitors" -Parameters $monitorParams
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Exporting account details" -PercentComplete 70
        $accountFile = Join-Path $OutputPath "AccountDetails"
        if ($accountResponse.account) {
            Write-LogMessage "Flattening account details." "Info"
            $flatAccount = Get-FlattenedObject -InputObject $accountResponse.account
            $flatAccount = Cleanse-Data -Data $flatAccount
            Write-LogMessage "Exporting account details to CSV and JSON." "Info"
            [PSCustomObject]$flatAccount | Export-Csv -Path "$accountFile.csv" -NoTypeInformation
            $accountResponse | ConvertTo-Json -Depth 20 | Out-File "$accountFile.json"
            Write-LogMessage "Account details exported successfully." "Info"
        }
        else {
            Write-LogMessage -Level Warning -Message "No account details found in the API response." "Warning"
        }
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Processing monitors" -PercentComplete 80
        $monitorsFile = Join-Path $OutputPath "Monitors"
        if ($monitorsResponse.monitors) {
            $monitorsArray = $monitorsResponse.monitors
            $flattenedMonitors = @()
            $batches = Get-Batches -Items $monitorsArray -BatchSize $BatchSize
            $totalBatches = $batches.Count
            $batchIndex = 0
            foreach ($batch in $batches) {
                $batchIndex++
                Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Processing monitors batch $batchIndex of $totalBatches" -PercentComplete (80 + (10 * $batchIndex / $totalBatches))
                foreach ($monitor in $batch) {
                    $flat = Get-FlattenedObject -InputObject $monitor
                    $flat = Cleanse-Data -Data $flat
                    $flattenedMonitors += [PSCustomObject]$flat
                }
            }
            Write-LogMessage "Exporting monitors data to CSV and JSON." "Info"
            $flattenedMonitors | Export-Csv -Path "$monitorsFile.csv" -NoTypeInformation
            $monitorsResponse | ConvertTo-Json -Depth 20 | Out-File "$monitorsFile.json"
            Write-LogMessage "Monitors exported successfully." "Info"
        }
        else {
            Write-LogMessage -Level Warning -Message "No monitors found in the API response." "Warning"
        }
        Write-Progress -Activity "Exporting UptimeRobot Data" -Status "Completed" -PercentComplete 100
        Write-LogMessage "Export-UptimeRobotData completed successfully." "Info"
    }
    catch {
        Write-LogMessage -Level Error -Message (Get-LocalizedMessage "ExportFailed" @($_)) "Error"
        throw
    }
    Write-LogMessage "Exiting Export-UptimeRobotData." "Info"
}

# --- Main Execution ---
Write-LogMessage "Script execution started." "Info"
try {
    Export-UptimeRobotData -OutputPath $OutputPath
    Write-LogMessage "Script execution completed successfully." "Info"
}
catch {
    Write-LogMessage -Level Error -Message (Get-LocalizedMessage "ScriptExecutionFailed" @($_)) "Error"
    exit 1
}
Write-LogMessage ("Telemetry: API Calls: {0}, Total Duration: {1} ms, Errors: {2}" -f $global:Telemetry.APICallCount, $global:Telemetry.TotalAPICallDuration, $global:Telemetry.APICallErrors) "Info"
