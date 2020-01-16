# ADC-19781
Several checks for CVE-2019-19781


## Module installation 
Download the two files and put them in one of the following locations:
- C:\Users\\%USERNAME%\Documents\WindowsPowerShell\Modules\ADC-19781
- C:\Program Files\WindowsPowerShell\Modules\ADC-19781

## Import Module
```powershell
Get-Module ADC-19781
```

There are three main functions:
- ADCTestExploit
- ADCCheckMitigation
- ADCFindIfHacked

### ADCTestExploit
External test to check if you have successfully applied the mitigation

```powershell
SYNTAX
    ADCTestExploit [-Uri] <string> [-PassThru]
```

```powershell
EXAMPLE
    PS C:\> ADCTestExploit -Uri "gateway.domain.com"
```

### ADCCheckMitigation
Check the Citrix ADC / NetScaler to verify if the mitigation is in place

```powershell
SYNTAX
    ADCCheckMitigation [-ManagementURL] <uri> [-Credential] <pscredential>
```

```powershell
EXAMPLE
    PS C:\> ADCCheckMitigation -ManagementURL "https://citrixnetscaler.domain.local"
```
NOTE: You can optionaly specify the -Credential <Credential> parameter, if not credential will be asked.

### ADCFindIfHacked
Execute some test to fid out if you are possibly hacked, this wil not give 100% certanty.
This is based on currently known facts.

```powershell
SYNTAX
    ADCFindIfHacked [-ManagementURL] <uri> [-Credential] <pscredential>
```

```powershell
EXAMPLE
    PS C:\> ADCFindIfHacked -ManagementURL "https://citrixnetscaler.domain.local"
```
NOTE: You can optionaly specify the -Credential <Credential> parameter, if not credential will be asked.

