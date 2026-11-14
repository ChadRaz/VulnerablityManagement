I have conducted a DISA STIG scan on a standard Windows 11 Pro Azure VM and programmatically remediated 10 STIGS with powershell. The Windows 11 Image is the standard"Windows 11 Pro, version 26H2 x64 Gen2." I disabled the Windows Defender Firewall so that the scan could probe the machine fully.

I conducted an initial DISA STIG Scan. The results are shown below:
<img width="699" height="118" alt="Screenshot 2026-11-14 120609" src="https://github.com/user-attachments/assets/17b347e3-4a13-47cb-a0de-4dac85f2be1d" />

I chose the following 10 vulnerabilities at random to remediate:

1.  [WN11-CC-000366](https://stigaview.com/products/win11/v2r11/WN11-CC-000366/): Windows 11 must be configured to prevent Windows apps from being activated by voice

2.  [WN11-CC-000110](https://stigaview.com/products/win11/v2r11/WN11-CC-000110/): Printing over HTTP must be prevented

3.  [WN11-EP-000310](https://stigaview.com/products/win11/v2r11/WN11-EP-000310/): Windows 11 Kernel (Direct Memory Access) DMA Protection must be enabled

4.  [WN11-CC-000280](https://stigaview.com/products/win11/v2r11/WN11-CC-000280/): Remote Desktop Services must always prompt a client for passwords upon connection

5.  [WN11-CC-000005](https://stigaview.com/products/win11/v2r11/WN11-CC-000005/): Camera access from the lock screen must be disabled

6.  [WN11-CC-000100](https://stigaview.com/products/win11/v2r11/WN11-CC-000100/): Downloading print driver packages over HTTP must be prevented

7.  [WN11-UR-000025](https://stigaview.com/products/win11/v2r11/WN11-UR-000025/): The "Allow log on locally" user right must only be assigned to the Administrators and Users groups

8.  [WN11-CC-000040](https://stigaview.com/products/win11/v2r11/WN11-CC-000040/): Insecure logons to an SMB server must be disabled

9.  [WN11-AU-000510](https://stigaview.com/products/win11/v2r11/WN11-AU-000510/): The System event log size must be configured to 32768 KB or greater

10. [WN11-CC-000145:](https://stigaview.com/products/win11/v2r11/WN11-CC-000145/) Users must be prompted for a password on resume from sleep (on battery)

The links attached to each STIG ID has a description on the misconfiguration, how to manually check for the misconfiguration, and how to manually remediate it. Using Claude, I have created programmatic powershell scripts to check for and remediate the misconfigurations. Both scripts and a screenshot of their execution on the scanned machine are located in the folder with the title being their STIG ID.

I conducted the same DISA STIG scan again after remediating the configurations: 
<img width="701" height="64" alt="Screenshot 2026-11-14 161843" src="https://github.com/user-attachments/assets/eafc7c94-722c-4a54-9ad5-becb8f7b0c30" />


As shown, 10 configurations were fixed. I went through and confirmed that the ones I remediated were the ones that changed the results.

The full scan results for both scans are located in the "Scan Reports" folder.
