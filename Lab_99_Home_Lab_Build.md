# Build Your Own PowerShell Badness Lab

This is a brief outline of the configuration steps used to build the hands on lab.
After building this in your own VM environment, you should be able to do these same labs after the conference.

Once you get the machines built, just copy over the PS1 files from this repo to a local folder `C:\Labs` on the Windows boxes.

## Windows Server
- Windows Server 2016
- Domain controller role
- Group policies linked to the root of the domain with the link disabled
    - Enable PowerShell logging and transcription
    - Disable Defender
- PowerShell remoting enabled by default

## Windows Client
- Windows 10
- Joined to domain
- [RSAT](https://docs.microsoft.com/en-us/windows-server/remote/remote-server-administration-tools) pre-installed (or [download here](https://www.microsoft.com/en-us/download/details.aspx?id=45520))
- An SSH client
    - [PuTTY](https://putty.org)
    - [Windows Subsystem for Linux (WSL)](https://docs.microsoft.com/en-us/windows/wsl/install-win10)
- Empty local folder `C:\badness`

## Linux
- [Kali Linux](https://www.kali.org/) or any Debian distro
- [PowerShell Core 6.2](https://github.com/powershell/powershell) installed
- [PowerShell Empire](http://www.powershellempire.com/) installed and left at defaults
- sshd configured for remote access with password authentication
- PowerShell policy JSON template file from [about_Logging_Non-Windows](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_non-windows?view=powershell-6#configuring-logging-on-non-windows-system)

If you have any question ping Ashley McGlone on Twitter [@GoateePFE](https://twitter.com/goateepfe).