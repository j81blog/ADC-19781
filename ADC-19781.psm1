#Thanks to the following posts:

#https://nerdscaler.com/2020/01/13/citrix-adc-cve-2019-19781-exploited-what-now/amp/
#https://isc.sans.edu/forums/diary/Citrix+ADC+Exploits+are+Public+and+Heavily+Used+Attempts+to+Install+Backdoor/25700
#https://isc.sans.edu/forums/diary/Some+Thoughts+About+the+Critical+Citrix+ADCGateway+Vulnerability+CVE201919781/25660
#http://deyda.net/index.php/en/2020/01/15/checklist-for-citrix-adc-cve-2019-19781/


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
        $TrustAll = $TAAssembly.CreateInstance("Local.ToolkitExtensions.Net.CertificatePolicy.TrustAll")
        [System.Net.ServicePointManager]::CertificatePolicy = $TrustAll
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

function ADCTestExploit {
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Uri,

        [parameter(Mandatory = $false)]
        [switch]$PassThru

    )
    #requires -version 5.1
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
    try {
        Get-Module Posh-SSH -ErrorAction Stop
    } catch {
        try {
            Install-Module Posh-SSH -ErrorAction Stop
        } catch {
            Write-Warning "Please install the PowerShell Module Posh-SSH, execute: `"Install-Module Posh-SSH`""
            Write-Warning "This is required to connect top the Citrix ADC / NetScaler to perfom some tests!"
            Exit 1
        }
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
    $ADCSession = Connect-ADC -ManagementURL $($ManagementURL.AbsoluteUri.TrimEnd("/")) -Credential $Credential -PassThru
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
        } else {
            Write-Host "Citrix ADC / NetScaler version OK"
        }
    } else {
        Write-Host "Citrix ADC / NetScaler version OK"
    }
    ""
    $SSHSession = New-SSHSession -ComputerName $ManagementURL.host -Credential $Credential

    $ShellCommand = 'shell ls /var/tmp/netscaler/portal/templates'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nThis command should return an error or no files, if not the NetScaler could possibly be hacked.`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell ls /var/vpn/bookmark/*.xml'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nIf there are XML files in this folder that are unknown, the NetScaler could possibly be hacked.`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell ls /netscaler/portal/templates/*.xml'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nIf there are XML files in this folder that are unknown, the NetScaler could possibly be hacked.`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    Write-Host -ForegroundColor White  "`r`nAttempts to exploit the system leave traces in the Apache httpaccess log files"

    Write-Warning  "Messages like `"GET /vpn/../vpns/portal/blkisazodfssy.xml HTTP/1.1`" could indicate a hack attempt"

    Write-Host -ForegroundColor White  "`r`nChecking Apache httpaccess log files"

    $ShellCommand = 'shell cat /var/log/httpaccess.log | grep vpns | grep xml'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell cat /var/log/httpaccess.log | grep "/\.\./"'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell gzcat /var/log/httpaccess.log.*.gz | grep vpns | grep xml'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell gzcat /var/log/httpaccess.log.*.gz | grep "/\.\./"'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White  "`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell "cat /var/log/httperror.log | grep -B2 -A5 Traceback"'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "Apache error logs`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell "gzcat /var/log/httperror.log.*.gz | grep -B2 -A5 Traceback"'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "Apache error logs`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell cat /var/log/bash.log | grep nobody'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`nBash logs, commands running as nobody could indicate an attack."
    Write-Warning "Beware, these logs rotate rather quickly (1-2 days)"
    Write-Host -ForegroundColor White "Command Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell gzcat /var/log/bash.*.gz | grep nobody'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`nBash logs, commands running as nobody could indicate an attack. `r`nNOTE: But beware, these logs rotate rather quickly (1-2 days)`r`n(shell gzcat /var/log/bash.*.gz | grep nobody):"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $Normal = @"
`r`nDone
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
 Done

"@
    Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
    Write-Host -ForegroundColor Green $Normal

    
    $ShellCommand = 'shell cat /etc/crontab'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`ncrontab Output`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $Normal = @"
 Done
root:*:0:0:Charlie &:/root:/usr/bin/bash
nsroot:*:0:0:Netscaler Root:/root:/netscaler/nssh
daemon:*:1:1:Owner of many system processes:/root:/nonexistent
operator:*:2:20:System &:/nonexistent:/nonexistent
bin:*:3:7:Binaries Commands and Source,,,:/:/nonexistent
nobody:*:65534:65534:Unprivileged user:/nonexistent:/nonexistent
sshd:*:65533:65533:SSHD User:/nonexistent:/nonexistent
nsmonitor:*:65532:65534:Netscaler Monitoring user:/var/nstmp/monitors:/nonexistent
 Done

"@
    $ShellCommand = 'shell cat /etc/passwd'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "Check if new users have been added to the password file`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
    Write-Host -ForegroundColor Green $Normal
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $OutputUsers = ($Output.Output)
    $Users = @()
    for ($i = 1; $i -lt ($OutputUsers.Count - 1); $i++) {
        $Users += $OutputUsers[$i].Split(":")[0]
    }
    
    Write-Host -ForegroundColor White "Check if users have cron jobs assigned.`r`nThe ERROR response just means that these users have no cron jobs assigned, which is normal behavior."
    ForEach ($User in $Users) {
        $ShellCommand = $("shell crontab -u {0} -l" -f $User)
        $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
        Write-Host -ForegroundColor White "Command Executed: '$ShellCommand':"
        Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"
    }
    
    $Normal = @"
 Done
root      12507  0.0  0.5 36972  7800  ??  Rs    9:32AM   0:00.06 nscli shell ps -aux | grep python \n
root      12508  0.0  0.1  9096  1344  ??  S     9:32AM   0:00.00 grep python

"@
    $ShellCommand = 'shell ps -aux | grep python'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`npython scripts`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare."
    Write-Host -ForegroundColor Green $Normal
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $Normal = @"
 Done
nsmonitor 75080  3.2  0.7 39092 12104  ??  S    Sun11AM 189:08.67 /usr/bin/perl -w /netscaler/monitors/nsldap.pl base=dc=domain,dc=local;bdn=svc_ldapread@domain.local;password=**********;
nsmonitor 19865  2.3  0.9 39092 14404  ??  S    Mon06PM  75:45.64 /usr/bin/perl -w /netscaler/monitors/nsldap.pl base=dc=domain,dc=local;bdn=svc_ldapread@domain.local;password=**********;
nsmonitor  1510  0.0  0.5 36188  7828  ??  S     1Jan20   5:04.00 /usr/bin/perl -w /netscaler/monitors/nssf.pl acctservice=0;storename=Store;backendserver=0;
root      12510  0.0  0.5 36972  7800  ??  Rs    9:32AM   0:00.06 nscli shell ps -aux | grep perl \n
root      12511  0.0  0.1  9096  1348  ??  S     9:32AM   0:00.00 grep perl

"@
    $ShellCommand = 'shell ps -aux | grep perl'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`nperl scripts`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor White "The following output is from a Non-Compromised system, please compare (not all scripts are bad, if in doubt verify)."
    Write-Host -ForegroundColor Green $Normal
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"

    $ShellCommand = 'shell top -n 10'
    $Output = Invoke-SSHCommand -Index $($SSHSession.SessionId) -Command $ShellCommand
    Write-Host -ForegroundColor White "`r`nTop 10 running processes, only NSPPE-xx should have high CPU`r`nCommand Executed: '$ShellCommand':"
    Write-Host -ForegroundColor Yellow -BackgroundColor Black "$($Output.Output | Out-String)"


    Write-Host -ForegroundColor White "Finished"

    Write-Warning "Please also check Firewall logs! Attackers might use a compromised NetScaler as a jump host."
}
