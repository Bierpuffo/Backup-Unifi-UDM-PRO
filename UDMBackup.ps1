<#
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
#>

[cmdletbinding(DefaultParametersetName="UsernamePassword")]
param(
		[Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
		[alias("Host")]
		[string]$UnifiIP,
		
		[Parameter(ParameterSetName="UsernamePassword",Mandatory=$true)]
		[alias("Username")]
		[string]$UnifiUserName,
		
		[Parameter(ParameterSetName="UsernamePassword",Mandatory=$true)]
		[alias("Password")]
		[string]$UnifiPassword,

        [Parameter(ParameterSetName="UnifiCredential",Mandatory=$true)]
        [Alias("Credential")]
        [ValidateScript({
            if ($_ -is [System.Management.Automation.PSCredential]) {
                $true
            }
            elseif ($_ -is [string]) {
                $Script:UnifiCredential=Get-Credential -Credential $_
                $true
            }
            else {
                Write-Error "You passed an unexpected object type for the credential (-UnifiCredential)"
			}
		})][object]$UnifiCredential,

        [Parameter(Mandatory=$true)]
        [Alias("Location")]
        [ValidateSet("local", "network")]
        [string]$BackupLocation,

		[Parameter(Mandatory=$true)]
		[alias("Target")]
		[string]$BackupTargetLocation,
		
		[Parameter(Mandatory=$false)]
		[string]$WinSCPAssembly = $null,

        [Parameter(ParameterSetName="UsernamePassword",Mandatory=$false)]
        [Alias('ShareUsername')]
        [string]$NetworkUsername, 

        [Parameter(ParameterSetName="UsernamePassword",Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [Alias("SharePassword")]
        [string]$NetworkPassword,

        [Parameter(ParameterSetName="NetworkCredential",Mandatory=$false)]
        [Alias("ShareCredential")]
        [ValidateScript({
            if ($_ -is [System.Management.Automation.PSCredential]) {
                $true
            }
            elseif ($_ -is [string]) {
                $Script:NetworkCredential=Get-Credential -Credential $_
                $true
            }
            else {
                Write-Error "You passed an unexpected object type for the credential (-NetworkCredential)"
			}
		})][object]$NetworkCredential
        
)

# Start region variables

# Set WinSCP variables

[string]$WinSCPSite = "https://winscp.net/eng/download.php"
[string]$WinSCPErrorSite = "https://winscp.net/eng/docs/message_net_operation_not_supported"
[string]$WinSCPAssemblyx86 = "C:\Program Files\WinSCP\WinSCPnet.dll"
[string]$WinSCPAssemblyx64 = "C:\Program Files (x86)\WinSCP\WinSCPnet.dll"

#End region variables

# Set copy backup variables

[string]$ScriptDateTime = (Get-Date).ToString("yyyyMMdd")
[string]$UnifiPath = "/data/unifi/data/backup/autobackup/"

# End region variables

# Start region backup to network share 

    If ($BackupLocation -eq 'network') {

        # Execute function to secure Network credentials
        if (-not([string]::IsNullOrWhiteSpace($NetworkCredential))) {
	        Write-Verbose "Using Network Credential"
        } 
        elseif ((-not([string]::IsNullOrWhiteSpace($NetworkUserName))) -and (-not([string]::IsNullOrWhiteSpace($NetworkPassword)))){
	        Write-Verbose "Using network Username / Password"
	        [pscredential]$NetworkCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $NetworkUserName, $(ConvertTo-SecureString -String $NetworkPassword -AsPlainText -Force)
        } 
        else {
	        Write-Verbose "No valid username/password or credential specified. Enter a username and password, e.g. `"root`""
	        [pscredential]$NetworkCredential = Get-Credential -Message "Unifi username and password:"
        }

        # Check for first available drive letter when using backup to network
        Write-Verbose "Search for the first available drive letter to use for the Set-PSDrive action"
        $DriveLetter = [char[]](67..90) | Where {(get-wmiobject win32_logicaldisk | select -expand DeviceID) -notcontains "$($_):"} | Select -first 1
        Write-Verbose "The letter $($DriveLetter) is temporary used for the network share"


        # Create a new drive for copying the backup file
        try {
            Write-Verbose "Check if there are any current connections to the backup share"
            $Instances = Get-CimInstance -Class Win32_NetworkConnection
            If ($instances -gt $Null) {

            ForEach ($instance in $instances | Where-Object {$_.RemoteName -match $BackupTargetLocation.Split('\')[2]})
                {
                   net use $instance.RemoteName /d | Out-Null
                }
            Write-Verbose "Network connections are closed"

            Start-Sleep -s 5
            }
            else {
                      
                Write-Verbose "There are no connections closed."            } 
            
            Write-Verbose "Create netwerkshare with drive letter: $($DriveLetter)"
            New-PSDrive -Name $DriveLetter -Root $BackupTargetLocation -PSProvider "FileSystem" -Credential $NetworkCredential -Scope Script| Out-Null
            }
        Catch [System.Runtime.InteropServices.ExternalException] {
            throw $($_.Exception.Message)
            
            }

    }
    Else {
        if ( -Not (Test-Path $BackupTargetLocation)) {
	        New-Item -Path $BackupTargetLocation -ItemType Directory -Force | out-null
}
    }

# End Region backup to network share

# Start region Unifi Credential

    if (-not([string]::IsNullOrWhiteSpace($UnifiCredential))) {
	    Write-Verbose "Using UnifiCredential"
    } 
    elseif ((-not([string]::IsNullOrWhiteSpace($UnifiUserName))) -and (-not([string]::IsNullOrWhiteSpace($UnifiPassword)))){
	    Write-Verbose "Using SSH Unifi Username / Password"
	    [pscredential]$UnifiCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist $UnifiUserName, $(ConvertTo-SecureString -String $UnifiPassword -AsPlainText -Force)
    } 
    else {
	    Write-Verbose "No valid username/password or credential specified. Enter a username and password, e.g. `"root`""
	    [pscredential]$UnifiCredential = Get-Credential -Message "Unifi username and password:"
    }

# End region Unifi Credential

# Start region Load WinSCP .NET assembly and copy backup file
Try{
    Try{
    
    # Load WinSCP .NET assembly
		
        Write-Verbose "Loading WinSCP .NET assembly"

        if (Test-Path $WinSCPAssemblyx64) {
			$WinSCPAssembly = $WinSCPAssemblyx64
		} 
        elseif (Test-Path $WinSCPAssemblyx86) {
			$WinSCPAssembly = $WinSCPAssemblyx86
		}
        else {
			start $WinSCPSite
			throw "The .NET Assembly could not be found"
			}

		Write-Verbose "Using: $WinSCPAssembly"
    
        Add-Type -Path "$WinSCPAssembly"
        Write-Verbose "Assembly successfully loaded"
    
    # Setup WinSCP session options
        
        Write-Verbose "Setup WinSCP session options"
        $WinSCPsessionOptions = New-Object WinSCP.SessionOptions
        $WinSCPsessionOptions.Protocol = [WinSCP.Protocol]::Scp
        $WinSCPsessionOptions.HostName = $UnifiIP
        $WinSCPsessionOptions.UserName = "$($UnifiCredential.Username)"
        $WinSCPsessionOptions.Password = "$($UnifiCredential.GetNetworkCredential().Password)"
        $WinSCPsessionOptions.GiveUpSecurityAndAcceptAnySshHostKey = $true
    
        $WinSCPsession = New-Object WinSCP.Session

    Try{
        Write-Verbose "Connecting"
		$WinSCPSession.Open($WinSCPsessionOptions)

        # Get list of files in the directory
        $directoryInfo = $WinSCPsession.ListDirectory($UnifiPath)
 
        # Select the most recent file
        $latest =
            $directoryInfo.Files |
            Where-Object { (-Not $_.IsDirectory) -and ($_.Name -notmatch 'autobackup_meta.json') } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
            Write-Verbose "The latest file is $($latest) and will be copied"
 
        # Any file at all?
        if ($latest -eq $Null)
        {
            Write-Verbose "No file found"
            exit 1
        }
        
        Write-Verbose "Try to download the backup file"
		$WinSCPTransferOptions = New-Object WinSCP.TransferOptions
		$WinSCPTransferOptions.TransferMode = [WinSCP.TransferMode]::Binary
		$WinSCPTransferResult = $WinSCPSession.GetFiles("$($latest.FullName)", "$($BackupTargetLocation)\$($latest.Name)", $False, $WinSCPTransferOptions)
        
        # $WinSCPCopy = $WinSCPsession.GetFileToDirectory($latest.FullName, $backuptargetlocation) | Out-Null

        #Write-Verbose "Throw on any error"
			$WinSCPTransferResult.Check()
	
			Write-Verbose "Print results"
			foreach ($transfer in $WinSCPTransferResult.Transfers) {
            $copiedfile = $transfer.FileName.Substring(35)
            Write-Verbose ("Upload of {0} succeeded" -f $copiedfile)
			}
		} finally {
			Write-Verbose "Disconnect, clean up"
			$WinSCPsession.Dispose()
		}
        }
    Finally {
            Write-Verbose "Remove temporary drive letter"  
            If ($BackupLocation -eq 'network') {
               Remove-PSDrive -Name $DriveLetter -Force
            Write-Verbose "Temporary drive letter removed" 
            }
        }
    }
Catch [System.IO.IOException]{
		Start $WinSCPErrorSite
		Write-Error "DLL was probably downloaded with Internet Explorer, unblock before extracting"
		throw $($_.Exception.Message)
    }
Finally {
        Write-Verbose "Copy of the Unifi DreamMachine (Pro) UDM-(PRO) successfull finished"
        } 