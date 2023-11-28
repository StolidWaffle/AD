# AD

While going thorugh the OSCP I have started creating my own PowerShell script (that will eventually be converted to .psm format) that can be used during penetration tests to pivot within an Active Directory environment. This module was built to support authorized penetration tests only.

As of now, the following PowerShell cmdlets have been created:
Create-CredentialObject -> Used by other functions within this script to create a PSObject for credentials
Encode-Command -> Useful for converting a malicious command into Base64 (Output prepends the necessary powershell parameters to execute the malicious command)
Execute-WMICommand -> Creates a CIMSession using the DCOM protocol to execute commands on the remote system.
Create-PSSession -> Automates the creation of a PSSession that can be connected to in order to execute commands on the remote system 
Generate-PowerShellPayload -> Creates a reverse shell payload that is Base64 encoded. Prompts for the attacker IP (LHOST) and listening port (LPORT)
Execute-DCOMCommand -> Leverages various DCOM lateral movement options to execute commands on remote systems. As of now multiple lateral movement techinques have been added, but need further testing. Techniques in use were pulled from a whitepaper by Cyber Reason (https://www.cybereason.com/blog/dcom-lateral-movement-techniques)
Exfil-Data -> Converts a file to Base64 format which is then POST'd back to an attacker controlled netcat listener. The netcat listener creates a .b64 object that can be decoded from base64 and used in further attacks.

Additional work to be done on this project to automate selection of DCOM lateral movement techniques, data exfiltration techniques, etc. 
