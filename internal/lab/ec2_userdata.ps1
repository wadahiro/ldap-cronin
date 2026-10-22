<powershell>
# ldap-cronin lab on EC2: makes this Windows Server the only domain controller of a new forest like the source of
# the configuration, for tests. It runs at every boot (persist) and stops at once when it has finished:
#   1. first boot: the local Administrator gets the password of the Systems Manager parameter, AD DS is installed
#      and the forest created; the server restarts;
#   2. next boot, as the domain's Administrator: a self-signed LDAPS certificate (the Samba lab's is self-signed
#      too), a password policy that takes the fixed password of the cloned users, an index on the marker attribute;
#      then C:\ldap-cronin\ready, which lab up --config waits for.
# The password is never in this script: it is read from the parameter, which lab up deletes once the lab is ready.
$ErrorActionPreference = 'Stop'
$Domain = '{{.Domain}}'
$NetBIOS = '{{.NetBIOS}}'
$Parameter = '{{.PasswordParameter}}'
$Region = '{{.Region}}'
$Marker = '{{.MarkerAttribute}}'
$ExtraName = '{{.LDAPSName}}'   # one more DNS name of the LDAPS certificate (empty: none)
$PlainLDAP = '{{if .LDAPPort}}yes{{end}}'   # clients bind over LDAP (389) without signing too (empty: as Windows has it)
$Dir = 'C:\ldap-cronin'
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
if (Test-Path "$Dir\ready") { exit 0 }
Start-Transcript -Append -Path "$Dir\setup.log"
try {
    $password = (Get-SSMParameter -Name $Parameter -WithDecryption $true -Region $Region).Value
    $secure = ConvertTo-SecureString $password -AsPlainText -Force
    if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) {
        Write-Output "creating the forest $Domain ($NetBIOS)"
        Set-LocalUser -Name Administrator -Password $secure
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBIOS -SafeModeAdministratorPassword $secure `
            -InstallDns -Force -NoRebootOnCompletion | Out-Null
        Restart-Computer -Force
        exit 0
    }
    $cred = New-Object System.Management.Automation.PSCredential("$NetBIOS\Administrator", $secure)
    for ($i = 0; ; $i++) {
        try { Get-ADDomain -Credential $cred | Out-Null; break }
        catch { if ($i -ge 60) { throw }; Start-Sleep -Seconds 10 }
    }
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
        Start-Sleep -Seconds 20
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
