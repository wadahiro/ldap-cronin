<powershell>
# ldap-cronin lab on EC2: makes this Windows Server the only domain controller of a new forest like the source of
# the configuration, for tests. It runs at every boot (persist) and stops at once when it has finished:
#   1. first boot: the local Administrator gets the password below, AD DS is installed
#      and the forest created; the server restarts;
#   2. next boot, as the domain's Administrator: a self-signed LDAPS certificate (the Samba lab's is self-signed
#      too), a password policy that takes the fixed password of the cloned users, an index on the marker attribute;
#      then C:\ldap-cronin\ready, which lab up --config waits for.
# The password is written below, for a lab to test with (the user's choice): it stays in the instance's user data,
# which its metadata and ec2:DescribeInstanceAttribute read. The transcript (setup.log) never holds it.
$ErrorActionPreference = 'Stop'
$Domain = '{{.Domain}}'
$NetBIOS = '{{.NetBIOS}}'
$Password = '{{.Password}}'
$Marker = '{{.MarkerAttribute}}'
$ExtraName = '{{.LDAPSName}}'   # one more DNS name of the LDAPS certificate (empty: none)
$PlainLDAP = '{{if .LDAPUnsigned}}yes{{end}}'   # a simple bind on 389 without signing taken (empty: as Windows has it)
$ForestMode = '{{.ForestMode}}'   # the source's functional levels (empty: the highest this Windows Server makes)
$DomainMode = '{{.DomainMode}}'
$RecycleBin = '{{if .RecycleBin}}yes{{end}}'   # the AD Recycle Bin enabled (empty: as Windows has it, off)
$Dir = 'C:\ldap-cronin'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
if (Test-Path "$Dir\ready") { exit 0 }
Start-Transcript -Append -Path "$Dir\setup.log"
try {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) {
        Write-Output "creating the forest $Domain ($NetBIOS)"
        Set-LocalUser -Name Administrator -Password $secure
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        $forest = @{ DomainName = $Domain; DomainNetbiosName = $NetBIOS; SafeModeAdministratorPassword = $secure
            InstallDns = $true; Force = $true; NoRebootOnCompletion = $true }
        if ($ForestMode) { $forest.ForestMode = $ForestMode; Write-Output "forest functional level $ForestMode" }
        if ($DomainMode) { $forest.DomainMode = $DomainMode; Write-Output "domain functional level $DomainMode" }
        Install-ADDSForest @forest | Out-Null
        Restart-Computer -Force
        exit 0
    }
    $cred = New-Object System.Management.Automation.PSCredential("$NetBIOS\Administrator", $secure)
    # Active Directory answers through its Web Services, which start minutes after the domain controller does, and
    # again after NTDS restarts: every step that asks it waits for it first (10 minutes at most).
    function Wait-AD {
        Write-Output 'waiting for Active Directory Web Services'
        for ($i = 0; ; $i++) {
            try { Get-ADDomain -Credential $cred | Out-Null; return }
            catch { if ($i -ge 60) { throw }; Start-Sleep -Seconds 10 }
        }
    }
    Wait-AD
    $fqdn = [System.Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
    $serverAuth = '1.3.6.1.5.5.7.3.1'
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains $serverAuth } | Select-Object -First 1
    if (-not $cert) {
        Write-Output "LDAPS certificate for $fqdn $ExtraName"
        $names = @($fqdn, $Domain)
        if ($ExtraName) { $names += $ExtraName }
        $cert = New-SelfSignedCertificate -DnsName $names -CertStoreLocation Cert:\LocalMachine\My `
            -KeyUsage DigitalSignature, KeyEncipherment -TextExtension "2.5.29.37={text}$serverAuth" -NotAfter (Get-Date).AddYears(5)
    }
    # The DC serves LDAPS with a certificate it trusts itself: a self-signed one goes to its trusted roots too, or
    # every TLS handshake on 636 is closed at once.
    if (-not (Test-Path "Cert:\LocalMachine\Root\$($cert.Thumbprint)")) {
        Write-Output "trusting the LDAPS certificate ($($cert.Thumbprint))"
        $root = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
        $root.Open('ReadWrite'); $root.Add($cert); $root.Close()
        Restart-Service NTDS -Force
        Wait-AD
    }
    if ($PlainLDAP) {
        # Signing not required (1), so a simple bind on 389 is taken, as Windows Server 2019 and 2022 do by default
        # (measured on 2019); 2025 requires signing for a new forest.
        $ntds = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters'
        if ((Get-ItemProperty -Path $ntds -Name LDAPServerIntegrity -ErrorAction SilentlyContinue).LDAPServerIntegrity -ne 1) {
            Write-Output 'LDAP without signing on 389'
            Set-ItemProperty -Path $ntds -Name LDAPServerIntegrity -Value 1 -Type DWord
        }
    }
    if ($RecycleBin) {
        $feature = Get-ADOptionalFeature -Credential $cred -Filter "name -eq 'Recycle Bin Feature'"
        if (-not $feature.EnabledScopes) {
            Write-Output 'AD Recycle Bin'
            Enable-ADOptionalFeature -Credential $cred -Identity $feature -Scope ForestOrConfigurationSet -Target $Domain -Confirm:$false
        }
    }
    Write-Output 'password policy for the fixed password of the cloned users'
    Set-ADDefaultDomainPasswordPolicy -Identity $Domain -Credential $cred -ComplexityEnabled $false -MinPasswordLength 1 `
        -PasswordHistoryCount 0 -MinPasswordAge 0 -MaxPasswordAge 0
    if ($Marker) {
        $schema = (Get-ADRootDSE -Credential $cred).schemaNamingContext
        $attr = Get-ADObject -Credential $cred -SearchBase $schema -Filter "lDAPDisplayName -eq '$Marker'" -Properties searchFlags
        if ($attr -and (($attr.searchFlags -band 1) -eq 0)) {
            Write-Output "index on $Marker"
            Set-ADObject -Credential $cred -Identity $attr -Replace @{ searchFlags = ($attr.searchFlags -bor 1) }
        }
    }
    New-Item -ItemType File -Force -Path "$Dir\ready" | Out-Null
    Write-Output 'ready'
} finally {
    Stop-Transcript
}
</powershell>
<persist>true</persist>
