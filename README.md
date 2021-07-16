.SYNOPSIS
	Download daily backup from the DreamMachine (UDM-PRO) and copy local or network
.DESCRIPTION
	Download daily backup from the DreamMachine (UDM-PRO) and copy local or network
.PARAMETER UnifiIP
	Unifi UDM-(PRO)/DreamMachine IP address, used to connect to the Unifi DreamMachine
.PARAMETER UnifiUsername
	Unifi username - use "root"
.PARAMETER UnifiPassword
	Unifi password - Configured in the Advnaced option of the DreamMachine
.PARAMETER Credential
	Use a PSCredential object instead of a username or password. Use "Get-Credential" to generate a credential object
	C:\PS> $Credential = Get-Credential
.PARAMETER WinSCPAssembly
	Specify the location for the WinSCP .NET assembly (Optional)
	When not specified the default location in the %ProgramFiles% / %ProgramFiles(x86)% will be used.
.PARAMETER BackupTargetLocation
	Specify the target location where to store the configuration. Select local or network in the BackupLocation parameter.
    i.e. C:\Backup or \\<fqdn>\Backup.
.PARAMETER BackupLocation
	Location for the Backup file. `"local`" or `"network`"
.EXAMPLE
    Copy backup file to a network share
	.\UDMBackup.ps1 -Host "192.168.1.1" -Username "root" -Password "P@ssw0rd" -Location "network" -Target "\\192.168.1.5\Backup\" -ShareUsername "domain\username" -SharePassword "P@ssw0rd" -verbose
	Download a backup from DreamMachine `"192.168.1.1`" and store it in `"\\192.168.1.5\Backup`". And generate verbose output.
.EXAMPLE
    Copy backup file to local disk
	.\UDMBackup.ps1 -Host "192.168.1.1" -Username "root" -Password "P@ssw0rd" -Location "local" -Target "C:\Backup" -verbose
	Download a backup from DreamMachine `"192.168.1.1`" and store it in `"C:\Backup`". And generate verbose output.
.EXAMPLE
    Copy backup file to local disk with the Get-Credentials option
	.\UDMBackup.ps1 -Host "192.168.1.1" -Credential $(get-credential) -Location "local" -Target "C:\Backup" -verbose
	Download a backup from DreamMachine `"192.168.1.1`" and store it in `"\\192.168.1.5\Backup`". And generate verbose output.
.NOTES
	File Name : UDMBackup.ps1
	Version   : v0.1
	Author	  : Sander Bierman
	Requires  : PowerShell v3 and up
	            Unifi DreamMachine (Pro) (UDM-PRO)
	            Run As Administrator
	            WinSCP
    Note      : Currently the Get-Credential is not working with the network share backup
.LINK
	https://www.automatedvision.info
