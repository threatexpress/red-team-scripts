# Red Team Scripts
---
Red Team Scripts is a collection of red teaming related tools, scripts, techniques, and notes developed or discovered over time during engagements. 
Related tool release blog posts can be found at [Threat Express](https://www.threatexpress.com) an Information Security Blog by MINIS.

## Situational Awareness

**Perform situational awareness on a local host or domain upon initial compromise.**

### `Invoke-HostEnum -Local`

**Author:** Andrew Chiles (@andrewchiles) with code by Joe Bialek, rvrsh3ll, Beau Bullock, and Tim Medin

A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration. However, domain enumeration is significantly limited with the intention that PowerView, BoodHound, etc will be also be used.

**Enumerated Information:**
    
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

**Credits:**

Several functions are inspired or pulled directly from the following projects and are referenced in the code where applicable:

[Invoke-HostRecon](https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1) by Beau Bullock 
[Get-ComputerDetails](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Get-ComputerDetails.ps1) from Joe Bialek in PowerSploit 
[Get-BrowserInformation](https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1) by rvrsh3ll 
[Get-UserSPNS](https://github.com/nidem/kerberoast) by Tim Medin 

## Usage

Refer to the help and comments in each script for detailed usage information.

## License

This project and all individual scripts are under the BSD 3-Clause license

## Links

[www.minis.io](http://www.minis.io)