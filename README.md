# UptimeRobotAccountBackup

**UptimeRobotAccountBackup** is a robust PowerShell script designed to retrieve your UptimeRobot account and monitor data and export it into CSV and JSON formats. Whether you’re migrating data or performing in‑depth analysis, this script provides comprehensive logging, secure API key management, external configuration, telemetry, batch processing, enhanced error recovery, and more.

---

## Features

- **Comprehensive Data Export:**  
  Retrieve all available account and monitor data from the UptimeRobot API and export it to CSV and JSON.

- **Detailed Logging:**  
  Built‑in logging (with localisation support) records all actions, errors, and performance telemetry.

- **External Configuration:**  
  Configure settings via a JSON file, which overrides command‑line parameters.

- **Secure API Key Management:**  
  Supports both plain text and SecureString API key inputs, as well as API key encryption with certificate-based decryption.

- **Batch Processing & Telemetry:**  
  Processes monitor records in batches and collects telemetry for operational insights.

- **Enhanced Error Recovery:**  
  Robust error handling and configurable retry logic for transient API failures.

- **Automated Documentation Generation:**  
  Generate documentation from the script’s comment‑based help with a single switch.

---

## Prerequisites

- **PowerShell 5.1+** (or PowerShell Core 7+)
- An active **UptimeRobot API key**
- (Optional) A certificate for decrypting an encrypted API key if using configuration file encryption

---

## Installation

Clone or download the repository and save the script as `Export-UptimeRobotData.ps1`.

---

## Usage

### Running the Script

Open a PowerShell terminal, navigate to the repository directory, and run the script:

```powershell
.\Export-UptimeRobotData.ps1 -ApiKey "YOUR_API_KEY" -OutputPath "C:\Exports"
```

Alternatively, if you prefer to supply a secure API key:

```powershell
.\Export-UptimeRobotData.ps1 -SecureApiKey (Read-Host -AsSecureString) -OutputPath "C:\Exports"
```

### Configuration File

You can override command‑line parameters by supplying a JSON configuration file. For example:

```json
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
```

Run the script with the configuration file:

```powershell
.\Export-UptimeRobotData.ps1 -ConfigFile ".\config.json" -EncryptionCertThumbprint "AB12CD34EF56" -OutputPath "C:\Exports"
```

### Documentation Generation

To generate Markdown documentation from the script’s comment‑based help, run:

```powershell
.\Export-UptimeRobotData.ps1 -GenerateDocs -OutputPath "C:\Exports"
```

No API key is required when generating documentation.

### Custom Uptime Ratios

To override the default uptime ratios, pass a comma‑separated list via the `-CustomUptimeRatios` parameter. If left empty, the parameter is omitted so the API uses its default values.

```powershell
.\Export-UptimeRobotData.ps1 -ApiKey "YOUR_API_KEY" -OutputPath "C:\Exports" -CustomUptimeRatios "1,7,30"
```

---

## Parameters

Below is a summary of key parameters:

- **-ApiKey**:  
  The UptimeRobot API key in plain text. Not required if `-GenerateDocs` is specified.

- **-SecureApiKey**:  
  A SecureString containing the UptimeRobot API key. Not required if `-GenerateDocs` is specified.

- **-OutputPath**:  
  Directory for saving exported CSV, JSON, and log files. Defaults to the current working directory.

- **-LogLevel**:  
  Logging level; accepts `Info`, `Warning`, or `Error`. Default is `Info`.

- **-MaxRetries**:  
  Maximum number of retry attempts for API calls (range 0–10). Default is `3`.

- **-RetryDelaySeconds**:  
  Delay in seconds between retry attempts (range 1–60). Default is `2`.

- **-RateLimitDelaySeconds**:  
  Delay in seconds after each successful API call for rate limiting (range 0–10). Default is `1`.

- **-BatchSize**:  
  Number of monitor records to process per batch. Default is `50`.

- **-ConfigFile**:  
  Path to a JSON configuration file that overrides command‑line parameters.

- **-Culture**:  
  Culture code for localised error messages (e.g., "en-US", "fr-FR"). Default is `en-US`.

- **-EncryptionCertThumbprint**:  
  Thumbprint of the certificate for decrypting an encrypted API key in the configuration file.

- **-GenerateDocs**:  
  Generates documentation from the script’s help comments and then exits.

- **-CustomUptimeRatios**:  
  A comma‑separated list of day values for uptime ratios. Each value must be between 1 and 10000. Default is `"1,7,30"`. If set to an empty string, the parameter is omitted from the API call.

---

## Examples

**Example 1:**  
Export data using a plain text API key:

```powershell
.\Export-UptimeRobotData.ps1 -ApiKey "YOUR_API_KEY" -OutputPath "C:\Exports"
```

**Example 2:**  
Export data using a secure API key from a configuration file with an encrypted key:

```powershell
.\Export-UptimeRobotData.ps1 -SecureApiKey (Read-Host -AsSecureString) -ConfigFile ".\config.json" -EncryptionCertThumbprint "AB12CD34EF56" -OutputPath "C:\Exports"
```

**Example 3:**  
Generate documentation:

```powershell
.\Export-UptimeRobotData.ps1 -GenerateDocs -OutputPath "C:\Exports"
```

---

## Related Links

- **UptimeRobot API:** [https://uptimerobot.com/api/](https://uptimerobot.com/api/)

---

## Contributing

Contributions, bug reports, and feature requests are welcome. Please submit issues or pull requests via GitHub.

---

## License

[MIT License](LICENSE)

---

This README is designed to provide clear guidance for users and contributors. For additional details or troubleshooting, please refer to the inline help within the script or contact the repository maintainer.
