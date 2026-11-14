I will be conducting a DISA STIG scan on a standard Windows 11 Pro Azure VM and programmatically remediating 10 STIGS with powershell. The Windows 11 Image is the standard"Windows 11 Pro, version 26H2 x64 Gen2." I disabled the Windows Defender Firewall so that the scan could probe the machine fully.

I conducted an initial DISA STIG Scan. The results are shown below:
<img width="837" height="137" alt="Screenshot 2026-11-14 131048" src="https://github.com/user-attachments/assets/840beffb-938d-4445-9d53-1926fdea62ab" />


I chose the following 10 vulnerabilities at random to remediate:

1.  [WN11-CC-000366](https://stigaview.com/products/win11/v2r11/WN11-CC-000366/): Windows 11 must be configured to prevent Windows apps from being activated by voice

2.  [WN11-CC-000110](https://stigaview.com/products/win11/v2r11/WN11-CC-000110/): Printing over HTTP must be prevented

3.  [WN11-00-000020](https://stigaview.com/products/win11/v2r11/WN11-00-000020/): Secure Boot must be enabled on Windows 11 systems

4.  [WN11-CC-000280](https://stigaview.com/products/win11/v2r11/WN11-CC-000280/): Remote Desktop Services must always prompt a client for passwords upon connection

5.  [WN11-CC-000005](https://stigaview.com/products/win11/v2r11/WN11-CC-000005/): Camera access from the lock screen must be disabled

6.  [WN11-CC-000100](https://stigaview.com/products/win11/v2r11/WN11-CC-000100/): Downloading print driver packages over HTTP must be prevented

7.  [WN11-UR-000025](https://stigaview.com/products/win11/v2r11/WN11-UR-000025/): The "Allow log on locally" user right must only be assigned to the Administrators and Users groups

8.  [WN11-CC-000040](https://stigaview.com/products/win11/v2r11/WN11-CC-000040/): Insecure logons to an SMB server must be disabled

9.  [WN11-AU-000510](https://stigaview.com/products/win11/v2r11/WN11-AU-000510/): The System event log size must be configured to 32768 KB or greater

10. [WN11-CC-000145:](https://stigaview.com/products/win11/v2r11/WN11-CC-000145/) Users must be prompted for a password on resume from sleep (on battery)

The links attached to each STIG ID has a description on the misconfiguration, how to manually check for the misconfiguration, and how to manually remediate it. Using Claude, I will create programmatic powershell scripts to check for and remediate the misconfigurations
