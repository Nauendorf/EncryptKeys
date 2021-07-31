function EncryptAPIKey
{
    [CmdletBinding()]
    param (       
        [Parameter(Mandatory = $true)]
        [string]
        $KeyName,
        [Parameter(Mandatory = $true)]
        [string]
        $KeyValue,
        [Parameter(DontShow)]
        [string]
        $CertName = "$KeyName" ,
        [Parameter(DontShow)]
        [string]
        $OutPath = $env:APPDATA + "\UserManagementTool\$CertName.enc"      
    )

    $ErrorActionPreference='stop'
    if ( $Host.Version.Major -lt 5 )
    { throw "$((Get-Host).Version) PowerShell version must be v5 or higher." }
    if ( !(Test-Path $OutPath) )
    { New-Item -ItemType File -Force -Path $OutPath | Out-Null }

    try {

        New-SelfSignedCertificate -DnsName $CertName `
                                  -CertStoreLocation "Cert:\CurrentUser\My" `
                                  -KeyUsage KeyEncipherment,DataEncipherment, KeyAgreement `
                                  -Type DocumentEncryptionCert | Out-Null;

        Protect-CmsMessage -Content "$KeyName=$KeyValue" `
                           -To "cn=$CertName" `
                           -OutFile $OutPath;                 

    }
    catch {
        throw $_.Exception
    }

    Write-Host "Key for $KeyName has been encrypted" 
}

function UnencryptAPIKey 
{
    [CmdletBinding()]
    param (
        [Parameter( 
            Mandatory = $true)]
        [validatescript({
            if (!(Test-Path $File)){throw "Path does not exist"}
            else { return $true }    
        })]
        [string[]]     
        $File,
        [Parameter(DontShow)]
        $r=@{}
    )

    $ErrorActionPreference='continue'
    
    foreach ($f in $File)
    {
        if ( (Get-Item $f).Name.Split('.')[0] -in ((Get-Childitem -Path Cert:\CurrentUser\My -DocumentEncryptionCert).DnsNameList.unicode) ) {

            $content = Unprotect-CmsMessage -Path $f            
            $r += @{"$($content.Split('=')[0])" = "$($content.Split('=')[1])"}           
        }
        else {
            Write-Warning "No matching certificate$($file.FullName)"
        }      
    }

    return $r
}
