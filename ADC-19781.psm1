#Thanks to the following posts:

#https://nerdscaler.com/2020/01/13/citrix-adc-cve-2019-19781-exploited-what-now/amp/
#https://isc.sans.edu/forums/diary/Citrix+ADC+Exploits+are+Public+and+Heavily+Used+Attempts+to+Install+Backdoor/25700
#https://isc.sans.edu/forums/diary/Some+Thoughts+About+the+Critical+Citrix+ADCGateway+Vulnerability+CVE201919781/25660
#http://deyda.net/index.php/en/2020/01/15/checklist-for-citrix-adc-cve-2019-19781/


function Ignore-SSLCertificates {
    $Provider = New-Object Microsoft.CSharp.CSharpCodeProvider
    $Provider.CreateCompiler() | Out-Null
    $Params = New-Object System.CodeDom.Compiler.CompilerParameters
    $Params.GenerateExecutable = $false
    $Params.GenerateInMemory = $true
    $Params.IncludeDebugInformation = $false
    $Params.ReferencedAssemblies.Add("System.DLL") > $null
    $TASource = @'
        namespace Local.ToolkitExtensions.Net.CertificatePolicy
        {
            public class TrustAll : System.Net.ICertificatePolicy
            {
                public bool CheckValidationResult(System.Net.ServicePoint sp,System.Security.Cryptography.X509Certificates.X509Certificate cert, System.Net.WebRequest req, int problem)
                {
                    return true;
                }
            }
        }
'@ 
    $TAResults = $Provider.CompileAssemblyFromSource($Params, $TASource)
    $TAAssembly = $TAResults.CompiledAssembly
    ## We create an instance of TrustAll and attach it to the ServicePointManager
    $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
    [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
    $AllProtocols = [Enum]::GetValues([System.Net.SecurityProtocolType])
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
}

function Connect-ADC {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [String]$ManagementURL,

        [parameter(Mandatory)]
        [PSCredential]$Credential,

        [int]$Timeout = 3600,

        [switch]$PassThru
    )
    # https://github.com/devblackops/NetScaler


    if ($ManagementURL -like "https://*") {
        #Write-ToLogFile -D -C Connect-ADC -M "SSL Connection, Trusting all certificates."
        Ignore-SSLCertificates
    }
    #Write-ToLogFile -I -C Connect-ADC -M "Connecting to $ManagementURL..."
    try {
        $login = @{
            login = @{
                Username = $Credential.Username;
                password = $Credential.GetNetworkCredential().Password
                timeout  = $Timeout
            }
        }
        $loginJson = ConvertTo-Json -InputObject $login -Compress
        $saveSession = @{ }
        $params = @{
            Uri             = "$ManagementURL/nitro/v1/config/login"
            Method          = 'POST'
            Body            = $loginJson
            SessionVariable = 'saveSession'
            ContentType     = 'application/json'
            ErrorVariable   = 'restError'
            Verbose         = $false
        }
        $response = Invoke-RestMethod @params

        if ($response.severity -eq 'ERROR') {
            #Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
            Write-Error "Error. See log"
            TerminateScript 1
        } else {
            #Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | Select-Object message,severity,errorcode | ConvertTo-Json -Compress)"
        }
    } catch [Exception] {
        throw $_
    }
    $session = [PSObject]@{
        ManagementURL = [String]$ManagementURL;
        WebSession    = [Microsoft.PowerShell.Commands.WebRequestSession]$saveSession;
        Username      = $Credential.Username;
        Version       = "UNKNOWN";
    }
    try {
        #Write-ToLogFile -D -C Connect-ADC -M "Trying to retrieve the ADC version"
        $params = @{
            Uri           = "$ManagementURL/nitro/v1/config/nsversion"
            Method        = 'GET'
            WebSession    = $Session.WebSession
            ContentType   = 'application/json'
            ErrorVariable = 'restError'
            Verbose       = $false
        }
        $response = Invoke-RestMethod @params
        #Write-ToLogFile -D -C Connect-ADC -M "Response: $($response | ConvertTo-Json -Compress)"
        $version = $response.nsversion.version.Split(",")[0]
        if (-not ([String]::IsNullOrWhiteSpace($version))) {
            $session.version = $version
        }
        #Write-ToLogFile -I -C Connect-ADC -M "Connected"
    } catch {
        #Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Exception Message: $($_.Exception.Message)"
        #Write-ToLogFile -E -C Connect-ADC -M "Response: $($response | ConvertTo-Json -Compress)"
    }
    $Script:NSSession = $session

    if ($PassThru) {
        return $session
    }
}

function Invoke-ADCRestApi {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$Session,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DELETE', 'GET', 'POST', 'PUT')]
        [String]$Method,

        [Parameter(Mandatory = $true)]
        [String]$Type,

        [String]$Resource,

        [String]$Action,

        [hashtable]$Arguments = @{ },

        [switch]$Stat = $false,

        [ValidateScript( { $Method -eq 'GET' })]
        [hashtable]$Filters = @{ },

        [ValidateScript( { $Method -ne 'GET' })]
        [hashtable]$Payload = @{ },

        [switch]$GetWarning = $false,

        [ValidateSet('EXIT', 'CONTINUE', 'ROLLBACK')]
        [String]$OnErrorAction = 'EXIT'
    )
    Ignore-SSLCertificates
    # https://github.com/devblackops/NetScaler
    if ([String]::IsNullOrEmpty($($Session.ManagementURL))) {
        #Write-ToLogFile -E -C Invoke-ADCRestApi -M "Probably not logged into the Citrix ADC!"
        throw "ERROR. Probably not logged into the ADC"
    }
    if ($Stat) {
        $uri = "$($Session.ManagementURL)/nitro/v1/stat/$Type"
    } else {
        $uri = "$($Session.ManagementURL)/nitro/v1/config/$Type"
    }
    if (-not ([String]::IsNullOrEmpty($Resource))) {
        $uri += "/$Resource"
    }
    if ($Method -ne 'GET') {
        if (-not ([String]::IsNullOrEmpty($Action))) {
            $uri += "?action=$Action"
        }

        if ($Arguments.Count -gt 0) {
            $queryPresent = $true
            if ($uri -like '*?action*') {
                $uri += '&args='
            } else {
                $uri += '?args='
            }
            $argsList = @()
            foreach ($arg in $Arguments.GetEnumerator()) {
                $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
            }
            $uri += $argsList -join ','
        }
    } else {
        $queryPresent = $false
        if ($Arguments.Count -gt 0) {
            $queryPresent = $true
            $uri += '?args='
            $argsList = @()
            foreach ($arg in $Arguments.GetEnumerator()) {
                $argsList += "$($arg.Name):$([System.Uri]::EscapeDataString($arg.Value))"
            }
            $uri += $argsList -join ','
        }
        if ($Filters.Count -gt 0) {
            $uri += if ($queryPresent) { '&filter=' } else { '?filter=' }
            $filterList = @()
            foreach ($filter in $Filters.GetEnumerator()) {
                $filterList += "$($filter.Name):$([System.Uri]::EscapeDataString($filter.Value))"
            }
            $uri += $filterList -join ','
        }
    }
    #Write-ToLogFile -D -C Invoke-ADCRestApi -M "URI: $uri"

    $jsonPayload = $null
    if ($Method -ne 'GET') {
        $warning = if ($GetWarning) { 'YES' } else { 'NO' }
        $hashtablePayload = @{ }
        $hashtablePayload.'params' = @{'warning' = $warning; 'onerror' = $OnErrorAction; <#"action"=$Action#> }
        $hashtablePayload.$Type = $Payload
        $jsonPayload = ConvertTo-Json -InputObject $hashtablePayload -Depth 100 -Compress
        #Write-ToLogFile -D -C Invoke-ADCRestApi -M "JSON Payload: $($jsonPayload | ConvertTo-Json -Compress)"
    }

    $response = $null
    $restError = $null
    try {
        $restError = @()
        $restParams = @{
            Uri           = $uri
            ContentType   = 'application/json'
            Method        = $Method
            WebSession    = $Session.WebSession
            ErrorVariable = 'restError'
            Verbose       = $false
        }

        if ($Method -ne 'GET') {
            $restParams.Add('Body', $jsonPayload)
        }

        $response = Invoke-RestMethod @restParams

        if ($response) {
            if ($response.severity -eq 'ERROR') {
                #Write-ToLogFile -E -C Invoke-ADCRestApi -M "Got an ERROR response: $($response| ConvertTo-Json -Compress)"
                throw "Error. See log"
            } else {
                #Write-ToLogFile -D -C Invoke-ADCRestApi -M "Response: $($response | ConvertTo-Json -Compress)"
                if ($Method -eq "GET") { 
                    return $response 
                }
            }
        }
    } catch [Exception] {
        if ($Type -eq 'reboot' -and $restError[0].Message -eq 'The underlying connection was closed: The connection was closed unexpectedly.') {
            #Write-ToLogFile -I -C Invoke-ADCRestApi -M "Connection closed due to reboot."
        } else {
            #Write-ToLogFile -E -C Invoke-ADCRestApi -M "Caught an error. Exception Message: $($_.Exception.Message)"
            throw $_
        }
    }
}

function CleanOutput {
    [cmdletbinding()]
    param(
        [parameter(Position = 0)]
        [String[]]$Data
    )
    [String[]]$Output = @()
    ForEach ($Line in $data) {
        if (-Not ($Line -Like " Done")) {
            $Output += $Line
        }
    }
    if ([String]::IsNullOrWhiteSpace($Output)) {
        $Output = "NO RESULTS FOUND"
    }
    if ($Output -eq "ERROR: ") {
        $Output = "NOT FOUND"
    }
    return $Output
}

function Write-ToLogFile {
    <#
.SYNOPSIS
    Write messages to a log file.
.DESCRIPTION
    Write info to a log file.
.PARAMETER Message
    The message you want to have written to the log file.
.PARAMETER Block
    If you have a (large) block of data you want to have written without Date/Component tags, you can specify this parameter.
.PARAMETER E
    Define the Message as an Error message.
.PARAMETER W
    Define the Message as a Warning message.
.PARAMETER I
    Define the Message as an Informational message.
    Default value: This is the default value for all messages if not otherwise specified.
.PARAMETER D
    Define the Message as a Debug Message
.PARAMETER Component
    If you want to have a Component name in your log file, you can specify this parameter.
    Default value: Name of calling script
.PARAMETER DateFormat
    The date/time stamp used in the LogFile.
    Default value: "yyyy-MM-dd HH:mm:ss:ffff"
.PARAMETER NoDate
    If NoDate is defined, no date String will be added to the log file.
    Default value: False
.PARAMETER Show
    Show the Log Entry only to console.
.PARAMETER LogFile
    The FileName of your log file.
    You can also define a (Global) variable in your script $LogFile, the function will use this path instead (if not specified with the command).
    Default value: <ScriptRoot>\Log.txt or if $PSScriptRoot is not available .\Log.txt
.PARAMETER Delimiter
    Define your Custom Delimiter of the log file.
    Default value: <TAB>
.PARAMETER LogLevel
    The Log level you want to have specified.
    With LogLevel: Error; Only Error (E) data will be written or shown.
    With LogLevel: Warning; Only Error (E) and Warning (W) data will be written or shown.
    With LogLevel: Info; Only Error (E), Warning (W) and Info (I) data will be written or shown.
    With LogLevel: Debug; All, Error (E), Warning (W), Info (I) and Debug (D) data will be written or shown.
    With LogLevel: None; Nothing will be written to disk or screen.
    You can also define a (Global) variable in your script $LogLevel, the function will use this level instead (if not specified with the command)
    Default value: Info
.PARAMETER NoLogHeader
    Specify parameter if you don't want the log file to start with a header.
    Default value: False
.PARAMETER WriteHeader
    Only Write header with info to the log file.
.PARAMETER ExtraHeaderInfo
    Specify a String with info you want to add to the log header.
.PARAMETER NewLog
    Force to start a new log, previous log will be removed.
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file"
    To write a message to a log file just specify the following command, it will be a default informational message.
.EXAMPLE
    Write-ToLogFile -E "This message will be written to a log file"
    To write a message to a log file just specify the following command, it will be a error message type.
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file" -NewLog
    To start a new log file (previous log file will be removed)
.EXAMPLE
    Write-ToLogFile "This message will be written to a log file"
    If you have the variable $LogFile defined in your script, the Write-ToLogFile function will use that LofFile path to write to.
    E.g. $LogFile = "C:\Path\LogFile.txt"
.NOTES
    Function Name : Write-ToLogFile
    Version       : v0.2.6
    Author        : John Billekens
    Requires      : PowerShell v5.1 and up
.LINK
    https://blog.j81.nl
#>
    #requires -version 5.1

    [CmdletBinding(DefaultParameterSetName = "Info")]
    Param
    (
        [Parameter(ParameterSetName = "Error", ValueFromPipeline, Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Warning", ValueFromPipeline, Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Info", ValueFromPipeline, Mandatory = $true, Position = 0)]
        [Parameter(ParameterSetName = "Debug", ValueFromPipeline, Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias("M")]
        [String[]]$Message,

        [Parameter(ParameterSetName = "Block", Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("B")]
        [object[]]$Block,

        [Parameter(ParameterSetName = "Block", Mandatory = $false)]
        [Alias("BI")]
        [Switch]$BlockIndent,

        [Parameter(ParameterSetName = "Error")]
        [Switch]$E,

        [Parameter(ParameterSetName = "Warning")]
        [Switch]$W,

        [Parameter(ParameterSetName = "Info")]
        [Switch]$I,

        [Parameter(ParameterSetName = "Debug")]
        [Switch]$D,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("C")]
        [String]$Component = $(try { $(Split-Path -Path $($MyInvocation.ScriptName) -Leaf) } catch { "LOG" }),

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Alias("ND")]
        [Switch]$NoDate,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [ValidateNotNullOrEmpty()]
        [Alias("DF")]
        [String]$DateFormat = "yyyy-MM-dd HH:mm:ss:ffff",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("S")]
        [Switch]$Show,

        [String]$LogFile = "$PSScriptRoot\Log.txt",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [String]$Delimiter = "`t",

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [ValidateSet("Error", "Warning", "Info", "Debug", "None", IgnoreCase = $false)]
        [String]$LogLevel,

        [Parameter(ParameterSetName = "Error")]
        [Parameter(ParameterSetName = "Warning")]
        [Parameter(ParameterSetName = "Info")]
        [Parameter(ParameterSetName = "Debug")]
        [Parameter(ParameterSetName = "Block")]
        [Alias("NH", "NoHead")]
        [Switch]$NoLogHeader,
        
        [Parameter(ParameterSetName = "Head")]
        [Alias("H", "Head")]
        [Switch]$WriteHeader,

        [Alias("HI")]
        [String]$ExtraHeaderInfo = $null,

        [Alias("NL")]
        [Switch]$NewLog
    )
    begin {
        # Set Message Type to Informational if nothing is defined.
        if ((-Not $I) -and (-Not $W) -and (-Not $E) -and (-Not $D) -and (-Not $Block) -and (-Not $WriteHeader)) {
            $I = $true
        }
        #Check if a log file is defined in a Script. If defined, get value.
        try {
            $LogFileVar = Get-Variable -Scope Global -Name LogFile -ValueOnly -ErrorAction Stop
            if (-Not [String]::IsNullOrWhiteSpace($LogFileVar)) {
                $LogFile = $LogFileVar
            
            }
        } catch {
            #Continue, no script variable found for LogFile
        }
        #Check if a LogLevel is defined in a script. If defined, get value.
        try {
            if ([String]::IsNullOrEmpty($LogLevel) -and (-Not $Block) -and (-Not $WriteHeader)) {
                $LogLevelVar = Get-Variable -Scope Global -Name LogLevel -ValueOnly -ErrorAction Stop
                $LogLevel = $LogLevelVar
            }
        } catch { 
            if ([String]::IsNullOrEmpty($LogLevel) -and (-Not $Block)) {
                $LogLevel = "Info"
            }
        }
        if (-Not ($LogLevel -eq "None")) {
            #Check if LogFile parameter is empty
            if ([String]::IsNullOrWhiteSpace($LogFile)) {
                if (-Not $Show) {
                    Write-Warning "Messages not written to log file, LogFile path is empty!"
                }
                #Only Show Entries to Console
                $Show = $true
            } else {
                #If Not Run in a Script "$PSScriptRoot" wil only contain "\" this will be changed to the current directory
                $ParentPath = Split-Path -Path $LogFile -Parent -ErrorAction SilentlyContinue
                if (([String]::IsNullOrEmpty($ParentPath)) -or ($ParentPath -eq "\")) {
                    $LogFile = $(Join-Path -Path $((Get-Item -Path ".\").FullName) -ChildPath $(Split-Path -Path $LogFile -Leaf))
                }
            }
            Write-Verbose "LogFile: $LogFile"
            #Define Log Header
            if (-Not $Show) {
                if (
                    (-Not ($NoLogHeader -eq $True) -and (-Not (Test-Path -Path $LogFile -ErrorAction SilentlyContinue))) -or 
                    (-Not ($NoLogHeader -eq $True) -and ($NewLog)) -or
                    ($WriteHeader)) {
                    $LogHeader = @"
**********************
LogFile: $LogFile
Start time: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Username: $([Security.Principal.WindowsIdentity]::GetCurrent().Name)
RunAs Admin: $((New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
Machine: $($Env:COMPUTERNAME) ($([System.Environment]::OSVersion.VersionString))
PSCulture: $($PSCulture)
PSVersion: $($PSVersionTable.PSVersion)
PSEdition: $($PSVersionTable.PSEdition)
PSCompatibleVersions: $($PSVersionTable.PSCompatibleVersions -join ', ')
BuildVersion: $($PSVersionTable.BuildVersion)
PSCommandPath: $($PSCommandPath)
LanguageMode: $($ExecutionContext.SessionState.LanguageMode)
"@
                    if (-Not [String]::IsNullOrEmpty($ExtraHeaderInfo)) {
                        $LogHeader += "`r`n"
                        $LogHeader += $ExtraHeaderInfo.TrimEnd("`r`n")
                    }
                    $LogHeader += "`r`n**********************`r`n"

                } else {
                    $LogHeader = $null
                }
            }
        } else {
            Write-Verbose "LogLevel is set to None!"
        }
        #Define date String to start log message with. If NoDate is defined no date String will be added to the log file.
        if (-Not ($LogLevel -eq "None")) {
            if (-Not ($NoDate) -and (-Not $Block) -and (-Not $WriteHeader)) {
                $DateString = "{0}{1}" -f $(Get-Date -Format $DateFormat), $Delimiter
            } else {
                $DateString = $null
            }
            if (-Not [String]::IsNullOrEmpty($Component) -and (-Not $Block) -and (-Not $WriteHeader)) {
                $Component = " {0}{1}{0}" -f $Delimiter, $Component.ToUpper()
            } else {
                $Component = "{0}{0}" -f $Delimiter
            }
            #Define the log sting for the Message Type
            if ($Block -or $WriteHeader) {
                $WriteLog = $true
            } elseif ($E -and (($LogLevel -eq "Error") -or ($LogLevel -eq "Warning") -or ($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
                Write-Verbose -Message "LogType: [Error], LogLevel: [$LogLevel]"
                $MessageType = "ERROR"
                $WriteLog = $true
            } elseif ($W -and (($LogLevel -eq "Warning") -or ($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
                Write-Verbose -Message "LogType: [Warning], LogLevel: [$LogLevel]"
                $MessageType = "WARN "
                $WriteLog = $true
            } elseif ($I -and (($LogLevel -eq "Info") -or ($LogLevel -eq "Debug"))) {
                Write-Verbose -Message "LogType: [Info], LogLevel: [$LogLevel]"
                $MessageType = "INFO "
                $WriteLog = $true
            } elseif ($D -and (($LogLevel -eq "Debug"))) {
                Write-Verbose -Message "LogType: [Debug], LogLevel: [$LogLevel]"
                $MessageType = "DEBUG"
                $WriteLog = $true
            } else {
                Write-Verbose -Message "No Log entry is made, LogType: [Error: $E, Warning: $W, Info: $I, Debug: $D] LogLevel: [$LogLevel]"
                $WriteLog = $false
            }
        } else {
            $WriteLog = $false
        }
    } process {

    } end {
        #Write the line(s) of text to a file.
        if ($WriteLog) {
            if ($WriteHeader) {
                $LogString = $LogHeader
            } elseif ($Block) {
                if ($BlockIndent) {
                    $BlockLineStart = "{0}{0}{0}" -f $Delimiter
                } else {
                    $BlockLineStart = ""
                }
                if ($Block -is [System.String]) {
                    $LogString = "{0]{1}" -f $BlockLineStart, $Block.Replace("`r`n", "`r`n$BlockLineStart")
                } else {
                    $LogString = "{0}{1}" -f $BlockLineStart, $($Block | Out-String).Replace("`r`n", "`r`n$BlockLineStart")
                }
                $LogString = "$($LogString.TrimEnd("$BlockLineStart").TrimEnd("`r`n"))`r`n"
            } else {
                $LogString = "{0}{1}{2}{3}" -f $DateString, $MessageType, $Component, $($Message | Out-String)
            }
            if ($Show) {
                "$($LogString.TrimEnd("`r`n"))"
                Write-Verbose -Message "Data shown in console, not written to file!"

            } else {
                if (($LogHeader) -and (-Not $WriteHeader)) {
                    $LogString = "{0}{1}" -f $LogHeader, $LogString
                }
                try {
                    if ($NewLog) {
                        try {
                            Remove-Item -Path $LogFile -Force -ErrorAction Stop
                            Write-Verbose -Message "Old log file removed"
                        } catch {
                            Write-Verbose -Message "Could not remove old log file, trying to append"
                        }
                    }
                    [System.IO.File]::AppendAllText($LogFile, $LogString, [System.Text.Encoding]::Unicode)
                    Write-Verbose -Message "Data written to LogFile:`r`n         `"$LogFile`""
                } catch {
                    #If file cannot be written, give an error
                    Write-Error -Category WriteError -Message "Could not write to file `"$LogFile`""
                }
            }
        } else {
            Write-Verbose -Message "Data not written to file!"
        }
    }
}


function ADCTestExploit {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Uri,

        [parameter(Mandatory = $false)]
        [switch]$PassThru

    )
    #requires -version 5.1
    Ignore-SSLCertificates
    $return = $false
    $exception = $null
    $params = @{
        "Uri"       = "$Uri/vpns/cfg/smb.conf"
        "Method"    = "GET"
        "UserAgent" = "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
        "Headers"   = @{
            "Accept"                    = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            "Accept-Language"           = "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0."
            "Accept-Encoding"           = "gzip, deflat"
            "DNT"                       = 1
            "NSC_USER"                  = "admin4123"
            "NSC_NONCE"                 = "123456"
            "NSC_CLIENTTYPE"            = "123"
            "Upgrade-Insecure-Requests" = 1  
        }     
    }
    try {
        $null = Invoke-RestMethod @params
        Write-Host -ForegroundColor Red "Mitigation NOT applied, got StatusCode: $($_.Exception.Response.StatusCode.value__)" -ErrorAction Stop
        $return = $false
    } catch {
        $exception = $_
        if (($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]403) -or ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]404)) {
            
            Write-Host -ForegroundColor Green "Mitigation applied, got StatusCode: $($_.Exception.Response.StatusCode.value__)"
            $return = $true
        } else {
            Write-Host -ForegroundColor Red "Mitigation NOT applied, got StatusCode: $($_.Exception.Response.StatusCode.value__) Host could also not be valid, visit https://support.citrix.com/article/CTX267027"
            $return = $false
        }
    }
    if ($PassThru) { 
        return $exception 
    } else { 
        return $return 
    }
    
}

function ADCCheckMitigation {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidatePattern('^(http[s]?)(:\/\/)([^\s,]+)')]
        [System.URI]$ManagementURL,

        [parameter(Mandatory = $true)]    
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential
    )
    #requires -version 5.1
    Ignore-SSLCertificates
    $mitigation = $false
    $VersionOK = $false

    $ADCSession = Connect-ADC -ManagementURL $($ManagementURL.AbsoluteUri.TrimEnd("/")) -Credential $Credential -PassThru
    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy
    ""
    Write-Warning "In Citrix ADC Release 12.1 builds before 51.16/51.19 and 50.31, a bug exists that affects responder"
    Write-Warning "and rewrite policies bound to VPN virtual servers causing them not to process the packets that"
    Write-Warning "matched policy rules. Citrix recommends customers update to an unaffected build for the mitigation"
    Write-Warning "steps to apply properly."
    Write-Host -ForegroundColor Yellow "`r`nCurrent version $($ADCSession.Version)`r`n"
    $versions = $ADCSession.Version | Select-String -Pattern '[0-9]{2}.[0-9]{1,}' -AllMatches
    $version = "{0}.{1}" -f $versions.Matches.Value[0], $versions.Matches.Value[1]
    if ($version -like "12.1.*") {
        if ((($version -ne "12.1.50.31") -and ($version -ne "12.1.51.16")) -and (-Not ([version]$version -ge [version]"12.1.51.19"))) {
            Write-Warning "You still might be vulnerable to CVE-2019-19781!"
            Write-Warning "Upgrade to a version higher than 12.1 build 51.16"
            $VersionOK = $false
        } else {
            Write-Host "Citrix ADC / NetScaler version OK"
            $VersionOK = $true
        }
    } else {
        Write-Host "Citrix ADC / NetScaler version OK"
        $VersionOK = $true
    }
    ""
    if ($VersionOK) {
        $ResponderPolicies = $response.responderpolicy | Where-Object { ($_.rule -like '*HTTP.REQ.URL.DECODE_USING_TEXT_MODE.CONTAINS("/vpns/")*') -and ($_.rule -like '*!CLIENT.SSLVPN.IS_SSLVPN*') -and ($_.rule -like '*HTTP.REQ.URL.DECODE_USING_TEXT_MODE.CONTAINS("/../")*') }
        if ([string]::IsNullOrEmpty($ResponderPolicies)) {
            Write-Host -ForegroundColor Red "No valid Responder Policy found!"
        } else { 
            ForEach ($ResponderPolicy in $ResponderPolicies) {
                Write-Host -ForegroundColor Green "Responder Policy found that matched [$($ResponderPolicy.name)]"
                $rsa = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderaction -Filter @{name = "/$($ResponderPolicy.action)/" }
                $rspbinding = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type responderpolicy_binding -Resource "$($ResponderPolicy.name)"
                if (($rsa.responderaction.target -like "*403*") -or ($rsa.responderaction.target -like "*404*")) {
                    Write-Host -ForegroundColor Green "Responder Action found that matched [$($rsa.responderaction.name)]"
                    if ($rspbinding.responderpolicy_binding.responderpolicy_responderglobal_binding.priority -match [regex]"^[\d\.]+$") {
                        Write-Host -ForegroundColor Green "Responder Policy is globaly bound [$($rspbinding.responderpolicy_binding.responderpolicy_responderglobal_binding.priority)]"
                        $mitigation = $true
                    } else {
                        Write-Host -ForegroundColor Red "Responder Policy is NOT globaly bound [$($rspbinding.responderpolicy_binding.responderpolicy_responderglobal_binding.priority)]"
                    }
                } else {
                    Write-Host -ForegroundColor Red "Responder Action NOT found!"
                }
            }
            try {
                if ($mitigation) {
                    $payload = @{"filename" = "rc.netscaler"; "filelocation" = "/nsconfig/" }
                    $content = $null
                    $response = Invoke-ADCRestApi -Session $ADCSession -Method GET -Type systemfile -Arguments $payload -ErrorAction Stop
                    if (-Not ([String]::IsNullOrWhiteSpace($response.systemfile.filecontent))) {
                        $content = [System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($response.systemfile.filecontent))
                    }
                    if ($content -like "*nsapimgr_wr.sh -ys skip_systemaccess_policyeval=0*") {
                        Write-Host -ForegroundColor Green "rc.netscaler file is modified"
                        $mitigation = $true
                    } else {
                        Write-Host -ForegroundColor Red "rc.netscaler file is NOT modified, please execute:`r`n`r`nshell `"sed -i '' '/skip_systemaccess_policyeval=0/d' /nsconfig/rc.netscaler`"`r`n`r`nAnd reboot your netscaler, view `"https://support.citrix.com/article/CTX267679`" for more information"
                        $mitigation = $false
                    }
                } 
            } catch {
                Write-Host -ForegroundColor Red "Could not verify the /nsconfig/rc.netscaler, please verify manually!"
                $mitigation = $false
            }
        }
    }
    if ($mitigation) {
        Write-Host -ForegroundColor Green "Mitigation successfully applied"
        return $true
    } else {
        Write-Host -ForegroundColor Red "Mitigation NOT applied"
        return $false
    }

}


function ADCFindIfHacked {
    <#
.SYNOPSIS
    Check you adc for possible hack attempts
.DESCRIPTION
    Check you adc for possible hack attempts. Please visit the following sites for more information and explanations:
    http://deyda.net/index.php/en/2020/01/15/checklist-for-citrix-adc-cve-2019-19781/
    https://nerdscaler.com/2020/01/13/citrix-adc-cve-2019-19781-exploited-what-now/amp/
    https://isc.sans.edu/forums/diary/Citrix+ADC+Exploits+are+Public+and+Heavily+Used+Attempts+to+Install+Backdoor/25700
    https://isc.sans.edu/forums/diary/Some+Thoughts+About+the+Critical+Citrix+ADCGateway+Vulnerability+CVE201919781/25660
.PARAMETER ManagementURL
    The URL of the management interface
    PS C:\>ADCFindIfHacked -ManagementURL "https://192.168.10.11"
.PARAMETER TimeOut
    The URL of the management interface
    PS C:\>ADCFindIfHacked -ManagementURL "https://192.168.10.11" -TimeOut 400
.PARAMETER Credential
    You can specify a credential object with this parameter. If non is specified a popup wil be shown.
    PS C:\>$Credential = Get-Credential nsroot
    PS C:\>ADCFindIfHacked -ManagementURL "https://192.168.10.11" -Credential $Credential
.PARAMETER LogFile
    Specify a custom path for your log file
    PS C:\>ADCFindIfHacked -ManagementURL "https://192.168.10.11" -LogFile "c:\Temp\Logfile.txt"
.PARAMETER LogFile
    Specify this parameter if you don't want a log file
    PS C:\>ADCFindIfHacked -ManagementURL "https://192.168.10.11" -NoLog
.EXAMPLE
    PS C:\> ADCCheckMitigation -ManagementURL "https://cns001.domain.local"
    Executing all check on Citrix ADC / NetScaler "cns001.domain.local" via https
.OUTPUTS
    Results of the commands executed against a Citrix ADC / NetScaler
.NOTES
    Function Name : ADCFindIfHacked.ps1
    Version       : v0.7.2
    Author        : John Billekens
    Requires      : PowerShell v5.1 and up
                    Posh-SSH (v2.2)
.LINK
    https://github.com/j81blog/ADC-19781
#>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true)]
        [ValidatePattern('^(http[s]?)(:\/\/)([^\s,]+)')]
        [System.URI]$ManagementURL,

        [parameter(Mandatory = $false)]
        [Int32]$TimeOut = 300,

        [parameter(Mandatory = $true)]    
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential,

        [parameter(Mandatory = $false)]
        [String]$LogFile = "$($Env:TEMP)\ADCFindIfHacked_$((get-date).ToString("yyyyMMdd-HHmmss")).txt",

        [parameter(Mandatory = $false)]
        [Switch]$NoLog

    )
    #requires -version 5.1
    if ($NoLog) {
        $Global:LogLevel = "None"
    } else {
        $Global:LogFile = $LogFile
    }
    Write-ToLogFile -I -C $null -M "Starting ADCFindIfHacked" -NewLog
    try {
        Import-Module Posh-ssh -ErrorAction Stop
        Write-ToLogFile -I -C Posh-ssh -M "Posh-SSH Module loaded"
    } catch {
        Write-Warning "Please install the PowerShell Module Posh-SSH, execute: `"Install-Module Posh-SSH`""
        Write-Warning "This is required to connect top the Citrix ADC / NetScaler to perform some tests!"
        Write-ToLogFile -W -C Posh-ssh -M "Please install the PowerShell Module Posh-SSH, execute: `"Install-Module Posh-SSH`""
        Write-ToLogFile -W -C Posh-ssh -M "This is required to connect top the Citrix ADC / NetScaler to perform some tests!"
        Write-ToLogFile -I -C Final -M "ADCFindIfHacked closed"
        throw "Posh-SSH not installed, please install module Posh-SSH to continue"
    }

    Write-Warning @"
The following tests are not a 100% guarantee that the Citrix ADC / NetScaler is not compromised!
Please verify manually if there is any doubt!

This "Test" is based on information found by the community, many thanks to all who have provided the information.
Sources:
- https://support.citrix.com/article/CTX267027
- https://nerdscaler.com/2020/01/13/citrix-adc-cve-2019-19781-exploited-what-now/amp/
- https://isc.sans.edu/forums/diary/Citrix+ADC+Exploits+are+Public+and+Heavily+Used+Attempts+to+Install+Backdoor/25700
- https://ctxpro.com/are-people-mining-bitcoin-on-your-netscaler-adc-using-cve-2019-19781/
- http://deyda.net/index.php/en/2020/01/15/checklist-for-citrix-adc-cve-2019-19781/

NOTE: The script is of my own and not the opinion of my employer!


"@
    try {    
        $SSHSession = New-SSHSession -ComputerName $ManagementURL.host -Credential $Credential
        Write-Host -ForegroundColor White "SSC Connection to `"$($ManagementURL.host)`" Connected: $($SSHSession.Connected)`r`n"
        Write-ToLogFile -I -C Connection -M "SSC Connection to `"$($ManagementURL.host)`" Connected: $($SSHSession.Connected)`r`n"
        $ShellCommand = 'show version'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        $Versions = (CleanOutput -Data $Output.Output).Replace("`t", "") | Select-String -Pattern '[0-9]{2}.[0-9]{1,}' -AllMatches
        $version = "{0}.{1}" -f $versions.Matches.Value[0], $versions.Matches.Value[1]
        Write-Warning "In Citrix ADC Release 12.1 builds before 51.16/51.19 and 50.31, a bug exists that affects responder"
        Write-Warning "and rewrite policies bound to VPN virtual servers causing them not to process the packets that"
        Write-Warning "matched policy rules. Citrix recommends customers update to an unaffected build for the mitigation"
        Write-Warning "steps to apply properly."
        Write-ToLogFile -W -C Version -M "In Citrix ADC Release 12.1 builds before 51.16/51.19 and 50.31, a bug exists that affects responder and rewrite policies bound to VPN virtual servers causing them not to process the packets that matched policy rules. Citrix recommends customers update to an unaffected build for the mitigation"
        Write-Host -ForegroundColor Yellow "`r`nCurrent version $($ADCSession.Version)`r`n"
        Write-ToLogFile -W -C Version -M "Current version $($ADCSession.Version)"
        if ($version -like "12.1.*") {
            if ((($version -ne "12.1.50.31") -and ($version -ne "12.1.51.16")) -and (-Not ([version]$version -ge [version]"12.1.51.19"))) {
                Write-Warning "You still might be vulnerable to CVE-2019-19781!"
                Write-Warning "Upgrade to a version higher than 12.1 build 51.16"
                Write-ToLogFile -W -C Version -M "You still might be vulnerable to CVE-2019-19781!"
                Write-ToLogFile -W -C Version -M "Upgrade to a version higher than 12.1 build 51.16"
            } else {
                Write-Host "Citrix ADC / NetScaler version OK"
                Write-ToLogFile -I -C Version -M "Citrix ADC / NetScaler version OK"

            }
        } else {
            Write-Host -ForegroundColor Green "Citrix ADC / NetScaler version OK"
            Write-ToLogFile -I -C Version -M "Citrix ADC / NetScaler version OK"
        }
        ""
        Write-Host -ForegroundColor White  "`r`nThis command should not return any results, if not the NetScaler could possibly be hacked."
        Write-ToLogFile -I -C $null -M "This command should not return any results, if not the NetScaler could possibly be hacked."
        $ShellCommand = 'shell ls /var/tmp/netscaler/portal/templates'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        Write-Host -ForegroundColor White  "`r`nIf there are XML files in this folder that are unknown, the NetScaler could possibly be hacked."
        Write-ToLogFile -I -C $null -M "If there are XML files in this folder that are unknown, the NetScaler could possibly be hacked."
        $ShellCommand = 'shell ls /var/vpn/bookmark/*.xml'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        Write-Host -ForegroundColor White  "`r`nIf there are XML files in this folder that are unknown, the NetScaler could possibly be hacked."
        Write-ToLogFile -I -C $null -M "If there are XML files in this folder that are unknown, the NetScaler could possibly be hacked."
        $ShellCommand = 'shell ls /netscaler/portal/templates/*.xml'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        Write-Host -ForegroundColor White  "`r`nAttempts to exploit the system leave traces in the Apache httpaccess log files"
        Write-ToLogFile -I -C $null -M "Attempts to exploit the system leave traces in the Apache httpaccess log files"

        Write-Host -ForegroundColor Green  "INFO: Messages like `"GET /vpn/../vpns/portal/blkisazodfssy.xml HTTP/1.1`" could indicate a hack attempt"
        Write-ToLogFile -I -C Example -M "Messages like `"GET /vpn/../vpns/portal/blkisazodfssy.xml HTTP/1.1`" could indicate a hack attempt"

        Write-Host -ForegroundColor White  "`r`nChecking Apache httpaccess log files"
        Write-ToLogFile -I -C $null -M "Checking Apache httpaccess log files"

        $ShellCommand = 'shell cat /var/log/httpaccess.log | grep vpns | grep xml'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell cat /var/log/httpaccess.log | grep "/\.\./"'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell gzcat /var/log/httpaccess.log.*.gz | grep vpns | grep xml'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell gzcat /var/log/httpaccess.log.*.gz | grep "/\.\./"'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell "cat /var/log/httperror.log | grep -B2 -A5 Traceback"'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "Apache error logs`r`nCommand Executed: '$ShellCommand':"
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell "gzcat /var/log/httperror.log.*.gz | grep -B2 -A5 Traceback"'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "Apache error logs`r`nCommand Executed: '$ShellCommand':"
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell cat /var/log/bash.log | grep nobody'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nBash logs, commands running as nobody could indicate an attack."
        Write-ToLogFile -I -C $null -M "Bash logs, commands running as nobody could indicate an attack."
        Write-Host -ForegroundColor Green  "INFO: Messages like `r`n<Local7.notice> ns bash[3632]: nobody on (null) shell_command=`"uname -a`"`r`ncould indicate a hack attempt."
        Write-ToLogFile -I -C Example -M "Messages like `"<Local7.notice> ns bash[3632]: nobody on (null) shell_command=`"uname -a`"`" could indicate a hack attempt"
        Write-Warning "Beware, these logs rotate rather quickly (1-2 days)"
        Write-ToLogFile -W -M "Beware, these logs rotate rather quickly (1-2 days)"
        Write-Host -ForegroundColor White "Command Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $ShellCommand = 'shell gzcat /var/log/bash.*.gz | grep nobody'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nBash logs, commands running as nobody could indicate an attack. `r`nNOTE: But beware, these logs rotate rather quickly (1-2 days)`r`n($ShellCommand):"
        Write-ToLogFile -I -C $null -M "Bash logs, commands running as nobody could indicate an attack."
        Write-ToLogFile -W -M "NOTE: But beware, these logs rotate rather quickly (1-2 days)"
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $Normal = @"

SHELL=/bin/sh
PATH=/netscaler:/etc:/bin:/sbin:/usr/bin:/usr/sbin
HOME=/var/log
#minute hour    mday    month   wday    who     command
0       *       *       *       *       root    newsyslog
0       0       *       *       *       root    purge_tickets.sh
#
# time zone change adjustment for wall cmos clock,
# does nothing, if you have UTC cmos clock.
# See adjkerntz(8) for details.
1,31    0-5     *       *       *       root    adjkerntz -a
*       *       *       *       *       root    nsfsyncd -p
49       0-23       *       *       *       root    nslog.sh dozip

"@

        Write-Host -ForegroundColor White "`r`ncrontab details"
        Write-ToLogFile -I -C $null -M "crontab details"
        Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
        Write-ToLogFile -I -C $null -M "The following output is from a Non-Compromised system, please compare."
        Write-Host -ForegroundColor Green $Normal
        Write-ToLogFile -I -C Example -M $Normal
        $ShellCommand = 'shell cat /etc/crontab'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"
        if (([version]$version).Major -eq 13) {
            $Normal = @"

# `$FreeBSD: release/8.4.0/etc/master.passwd 243948 2012-12-06 11:54:25Z rwatson $
#
root:*:0:0:Charlie &:/root:/usr/bin/bash
nsroot:*:0:0:Netscaler Root:/root:/netscaler/nssh
daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
operator:*:2:5:System &:/:/usr/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
games:*:7:13:Games pseudo-user:/usr/games:/usr/sbin/nologin
news:*:8:8:News Subsystem:/:/usr/sbin/nologin
man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
_pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
_dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/sbin/nologin
pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
nsmonitor:*:65532:65534:Netscaler Monitoring user:/var/nstmp/monitors:/usr/sbin/nologin

"@
        } else {
            $Normal = @"

root:*:0:0:Charlie &:/root:/usr/bin/bash
nsroot:*:0:0:Netscaler Root:/root:/netscaler/nssh
daemon:*:1:1:Owner of many system processes:/root:/nonexistent
operator:*:2:20:System &:/nonexistent:/nonexistent
bin:*:3:7:Binaries Commands and Source,,,:/:/nonexistent
nobody:*:65534:65534:Unprivileged user:/nonexistent:/nonexistent
sshd:*:65533:65533:SSHD User:/nonexistent:/nonexistent
nsmonitor:*:65532:65534:Netscaler Monitoring user:/var/nstmp/monitors:/nonexistent

"@
        }
        Write-Host -ForegroundColor White "Check if new users have been added to the password file`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C $null -M "Check if new users have been added to the password file."
        Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
        Write-ToLogFile -I -C $null -M "The following output is from a Non-Compromised system, please compare."
        Write-Host -ForegroundColor Green $Normal
        Write-ToLogFile -I -C Example -M $Normal
        $ShellCommand = 'shell cat /etc/passwd'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $OutputUsers = ($Output.Output)
        $Users = @()
        for ($i = 1; $i -lt ($OutputUsers.Count - 1); $i++) {
            $Users += $OutputUsers[$i].Split(":")[0]
        }
    
        Write-Host -ForegroundColor White "Check if users have cron jobs assigned."
        Write-ToLogFile -I -C $null -M "Check if users have cron jobs assigned."
        ForEach ($User in $Users) {
            $ShellCommand = $("shell crontab -u {0} -l" -f $User)
            $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
            Write-Host -ForegroundColor White "Command Executed: '$ShellCommand':"
            Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
            Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
            Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"
        }
    
        $Normal = @"

root      12507  0.0  0.5 36972  7800  ??  Rs    9:32AM   0:00.06 nscli shell ps -aux | grep python \n
root      12508  0.0  0.1  9096  1344  ??  S     9:32AM   0:00.00 grep python

"@
        Write-Host -ForegroundColor White "`r`npython scripts"
        Write-ToLogFile -I -C $null -M "python scripts"
        Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
        Write-ToLogFile -I -C $null -M "The following output is from a Non-Compromised system, please compare."
        Write-Host -ForegroundColor Green $Normal
        Write-ToLogFile -I -C Example -M $Normal
        $ShellCommand = 'shell ps -aux | grep python'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $Normal = @"

nsmonitor 75080  3.2  0.7 39092 12104  ??  S    Sun11AM 189:08.67 /usr/bin/perl -w /netscaler/monitors/nsldap.pl base=dc=domain,dc=local;bdn=svc_ldapread@domain.local;password=**********;
nsmonitor 19865  2.3  0.9 39092 14404  ??  S    Mon06PM  75:45.64 /usr/bin/perl -w /netscaler/monitors/nsldap.pl base=dc=domain,dc=local;bdn=svc_ldapread@domain.local;password=**********;
nsmonitor  1510  0.0  0.5 36188  7828  ??  S     1Jan20   5:04.00 /usr/bin/perl -w /netscaler/monitors/nssf.pl acctservice=0;storename=Store;backendserver=0;
root      12510  0.0  0.5 36972  7800  ??  Rs    9:32AM   0:00.06 nscli shell ps -aux | grep perl \n
root      12511  0.0  0.1  9096  1348  ??  S     9:32AM   0:00.00 grep perl

"@
        Write-Host -ForegroundColor White "`r`nperl scripts"
        Write-ToLogFile -I -C $null -M "perl scripts"
        Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
        Write-ToLogFile -I -C $null -M "The following output is from a Non-Compromised system, please compare."
        Write-Host -ForegroundColor Green $Normal
        Write-ToLogFile -I -C Example -M $Normal
        $ShellCommand = 'shell ps -aux | grep perl'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        $Normal = @"

nobody    34839  0.0  0.5 114288 38836  ??  S     6:00PM   0:01.73 | |-- /bin/httpd
nobody    34840  0.0  0.5 114288 38892  ??  S     6:00PM   0:01.86 | |-- /bin/httpd
nobody    34841  0.0  0.5 120468 43084  ??  S     6:00PM   0:01.34 | |-- /bin/httpd
nobody    34842  0.0  0.5 120432 41764  ??  S     6:00PM   0:00.67 | |-- /bin/httpd
nobody    34843  0.0  0.4 114088 34608  ??  I     6:00PM   0:00.00 | `-- /bin/httpd
root      38520  0.0  0.0  9096  1432   0  S+    8:22PM   0:00.00 |     |-- grep nobody

"@
        Write-Host -ForegroundColor White "`r`nRunning processes for nobody"
        Write-ToLogFile -I -C $null -M "Running processes for nobody"
        Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
        Write-ToLogFile -I -C $null -M "The following output is from a Non-Compromised system, please compare."
        Write-Host -ForegroundColor Green $Normal
        Write-ToLogFile -I -C Example -M $Normal
        $ShellCommand = 'shell ps auxd | grep nobody'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"

        Write-Host -ForegroundColor White "`r`nTop 10 running processes, only NSPPE-xx should have high CPU"
        Write-ToLogFile -I -C $null -M "Top 10 running processes, only NSPPE-xx should have high CPU"
        $ShellCommand = 'shell top -n 10'
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand -TimeOut $TimeOut
        Write-Host -ForegroundColor White "`r`nCommand Executed: '$ShellCommand':"
        Write-ToLogFile -I -C Command -M "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow "$(CleanOutput -Data $Output.Output | Out-String)"
        Write-ToLogFile -I -C Output -M "`r`n$(CleanOutput -Data $Output.Output | Out-String)"
        "`r`n`r`n"
        Write-Warning "There might be more/other errors!`r`nWhen in doubt manually view the log files with the following commands:`r`nshell cat /var/log/httperror.log`r`nshell gzcat /var/log/httperror.log.*.gz"
        Write-ToLogFile -W -C Important-M "There might be more/other errors!"
        Write-ToLogFile -W -C Important -M "When in doubt manually view the log files with the following commands:"
        Write-ToLogFile -W -C Important -M "shell cat /var/log/httperror.log"
        Write-ToLogFile -W -C Important -M "shell gzcat /var/log/httperror.log.*.gz"
        "`r`n"
        Write-Warning "Please also check Firewall logs! Attackers might use a compromised NetScaler as a jump host."
        Write-ToLogFile -W -C Important -M "Please also check Firewall logs! Attackers might use a compromised NetScaler as a jump host."
        "`r`n`r`n"
        if (-Not $NoLog) {
            Write-Host -ForegroundColor Yellow "Session info saved in log file: $LogFile"
            "`r`n`r`n"
        }
        if (Remove-SSHSession -SessionId $($SSHSession.SessionId)) {
            Write-ToLogFile -I -C Posh-SSH -M "Sucessfully disconnected."
        } else {
            Write-ToLogFile -E -C Posh-SSH -M "Posh-SSH NOT disconnected."
        }
        Write-Host -ForegroundColor White "Finished`r`n"
        Write-ToLogFile -I -C $null -M "Finished"
    } catch {
        Write-ToLogFile -E -C Connect-ADC -M "Caught an error. Exception Message: $($_.Exception.Message)"
        Write-Error $_.Exception.Message
    }

}
