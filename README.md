# Red Team Scripts
---
Red Team Scripts is a collection of red teaming related tools, scripts, techniques, and notes developed or discovered over time during engagements. 
Related tool release blog posts can be found at [Threat Express](http://threatexpress.com) an Information Security and Red Teaming Blog

## Situational Awareness

**Perform situational awareness on a local host or domain upon initial compromise.**

### `enumerate.cna`

Cobalt Strike Aggressor script function and alias to perform some rudimentary Windows host enumeration with Beacon built-in commands (i.e. no Powershell, binary calls, or process injection). Additionally, adds a basic `enumerate` alias for Linux based systems in SSH sessions.


### `Invoke-HostEnum`

**Author:** Andrew Chiles (@andrewchiles) with code by harmj0y, Joe Bialek, rvrsh3ll, Beau Bullock, Tim Medin

A PowerShell v2.0 compatible script comprised of multiple system enumeration / situational awareness techniques collected over time. If system is a member of a Windows domain, it can also perform limited domain enumeration with the -Domain switch. However, domain enumeration is significantly limited with the intention that PowerView or BoodHound could also be used.

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

**Privilege Escalation**

Optionally performs Privilege Escalation functions from PowerUp in the PowerSploit project.

**Empire 2.0 Integration**

Use the accompanying hostenum.py script to include Invoke-HostEnum as post-exploitation situational awarness module in Empire. Both files need to be copied to the appropriate locations in Empire.

**Credits:**

Several functions are inspired or pulled directly from the following projects and are referenced in the code where applicable:

- [Invoke-HostRecon](https://raw.githubusercontent.com/dafthack/HostRecon/master/HostRecon.ps1) by Beau Bullock 
- [Get-ComputerDetails](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/Get-ComputerDetails.ps1) from Joe Bialek in PowerSploit 
- [Get-BrowserInformation](https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Get-BrowserData.ps1) by rvrsh3ll 
- [Get-UserSPNS](https://github.com/nidem/kerberoast) by Tim Medin 
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) by @harmj0y

## Usage

Refer to the help and comments in each script for detailed usage information.

## License

This project and all individual scripts are under the BSD 3-Clause license

## Links

[threatexpress.com](http://threatexpress.com)
http://threatexpress.com/2018/01/hostenum-updates-usage/
http://threatexpress.com/2017/05/invoke-hostenum/
