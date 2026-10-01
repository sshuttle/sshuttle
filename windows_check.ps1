[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string] $SSHLocation,

    [ValidateNotNullOrEmpty()]
    [string] $Key
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-ApplicationPath {
    param([Parameter(Mandatory)] [string] $Name)

    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        return $null
    }

    return [string] $command.Path
}

function Add-DirectoryToPath {
    param([Parameter(Mandatory)] [string] $Directory)

    $resolvedDirectory = [IO.Path]::GetFullPath($Directory).TrimEnd('\')
    $pathEntries = @($env:Path -split ';')
    if ($pathEntries.TrimEnd('\') -notcontains $resolvedDirectory) {
        $env:Path = "$resolvedDirectory;$env:Path"
    }
}

function Format-CommandArgument {
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Value)

    if ($Value -and $Value -notmatch '[\s"]') {
        return $Value
    }

    # CommandLineToArgvW rules: backslashes are only special when they precede a quote, including the closing one.
    $escaped = $Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1'
    return '"{0}"' -f $escaped
}

function Write-CommandPreview {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $ArgumentList = @()
    )

    $arguments = @($ArgumentList | ForEach-Object { Format-CommandArgument -Value $_ })
    Write-Verbose ("Executing: {0} {1}" -f (Format-CommandArgument -Value $FilePath), ($arguments -join ' ')).TrimEnd()
}

function Invoke-NativeProcess {
    param(
        [Parameter(Mandatory)] [string] $FilePath,
        [string[]] $ArgumentList = @(),
        [ValidateRange(1, 300)] [int] $TimeoutSeconds = 10
    )
    Write-CommandPreview -FilePath $FilePath -ArgumentList $ArgumentList
    $stdoutPath = [IO.Path]::GetTempFileName()
    $stderrPath = [IO.Path]::GetTempFileName()
    $stdinPath = [IO.Path]::GetTempFileName()
    $process = $null
    try {
        $startArguments = @{
            FilePath = $FilePath
            NoNewWindow = $true
            PassThru = $true
        }
        if ($ArgumentList.Count -gt 0) {
            $startArguments['ArgumentList'] = (($ArgumentList | ForEach-Object { Format-CommandArgument -Value $_ }) -join ' ')
        }
        $startArguments['RedirectStandardInput'] = $stdinPath
        $startArguments['RedirectStandardOutput'] = $stdoutPath
        $startArguments['RedirectStandardError'] = $stderrPath

        $process = Start-Process @startArguments
        # Caching the handle keeps ExitCode readable after the process exits.
        [void] $process.Handle
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)
        if (-not $completed) {
            Write-Verbose "Command timed out after $TimeoutSeconds seconds; terminating process $($process.Id)."
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
            }
            catch {
                Write-Verbose "Process exited while it was being terminated: $_"
            }
            [void] $process.WaitForExit(2000)
        }
        else {
            $process.WaitForExit()
            $process.Refresh()
        }

        $standardOutput = Get-Content -Path $stdoutPath -Raw -ErrorAction SilentlyContinue
        $standardError = Get-Content -Path $stderrPath -Raw -ErrorAction SilentlyContinue
        $exitCode = $null
        if ($completed) {
            try {
                if ($null -ne $process.ExitCode) {
                    $exitCode = [int] $process.ExitCode
                }
            }
            catch {
                Write-Verbose "Exit code was unavailable for process $($process.Id): $_"
            }
        }
        return [PSCustomObject]@{
            Completed = $completed
            ExitCode = $exitCode
            StandardOutput = [string] $standardOutput
            StandardError = [string] $standardError
        }
    }
    finally {
        Remove-Item -Path $stdinPath, $stdoutPath, $stderrPath -Force -ErrorAction SilentlyContinue
        if ($process) {
            $process.Dispose()
        }
    }
}

function Get-SupportedPython {
    $pythonPath = Get-ApplicationPath -Name 'python.exe'
    if (-not $pythonPath) {
        $pythonPath = Get-ApplicationPath -Name 'python3.exe'
    }
    if (-not $pythonPath) {
        throw 'Python 3.10 or newer is required, and python.exe must be available on PATH.'
    }

    Write-CommandPreview -FilePath $pythonPath -ArgumentList @('-c', 'import sys; print(sys.version_info.major, sys.version_info.minor, sys.version_info.micro, sep=chr(46))')
    $versionOutput = & $pythonPath -c 'import sys; print(sys.version_info.major, sys.version_info.minor, sys.version_info.micro, sep=chr(46))' 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $versionOutput) {
        throw "Unable to run Python at '$pythonPath'. Python 3.10 or newer must be available on PATH."
    }

    $pythonVersion = $null
    $versionText = [string] ($versionOutput | Select-Object -Last 1)
    if (-not [version]::TryParse($versionText.Trim(), [ref] $pythonVersion) -or
        $pythonVersion -lt [version] '3.10') {
        throw "Python 3.10 or newer is required; '$pythonPath' reports version $versionText."
    }

    return $pythonPath
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function ConvertTo-PowerShellLiteral {
    param([Parameter(Mandatory)] [string] $Value)

    # PowerShell also treats typographic single quotes as quote delimiters.
    $quoteCharacters = "['$([char]0x2018)$([char]0x2019)$([char]0x201A)$([char]0x201B)]"
    return "'$($Value -replace $quoteCharacters, '$0$0')'"
}

function ConvertTo-AbsolutePathLiteral {
    param([Parameter(Mandatory)] [string] $Path)

    return ConvertTo-PowerShellLiteral -Value $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function Start-ElevatedPowerShell {
    param(
        [string] $RequestedSSHLocation,
        [string] $RequestedKey,
        [switch] $RequestedVerbose
    )

    $powerShellPath = (Get-Process -Id $PID).Path
    if (-not $powerShellPath) {
        throw 'Unable to determine the current PowerShell executable for elevation.'
    }

    if (-not $PSCommandPath) {
        throw 'Unable to determine the script path for elevation; run this script from a .ps1 file.'
    }

    # Elevated processes ignore -WorkingDirectory, so restore it and pass absolute paths.
    $command = "Set-Location -LiteralPath $(ConvertTo-PowerShellLiteral -Value (Get-Location).ProviderPath); "
    $command += "& $(ConvertTo-PowerShellLiteral -Value $PSCommandPath)"
    if ($RequestedSSHLocation) {
        $command += " -SSHLocation $(ConvertTo-AbsolutePathLiteral -Path $RequestedSSHLocation)"
    }
    if ($RequestedKey) {
        $command += " -Key $(ConvertTo-AbsolutePathLiteral -Path $RequestedKey)"
    }
    if ($RequestedVerbose) {
        $command += ' -Verbose'
    }

    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $arguments = @(
        '-NoExit'
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-EncodedCommand'
        $encodedCommand
    )

    Write-CommandPreview -FilePath $powerShellPath -ArgumentList $arguments
    Start-Process -FilePath $powerShellPath -Verb RunAs -ArgumentList $arguments | Out-Null
}

function Confirm-Action {
    param([Parameter(Mandatory)] [string] $Message)

    $answer = Read-Host "$Message [y/N]"
    return $answer -match '^(?i:y|yes)$'
}

function Ensure-Administrator {
    if (Test-IsAdministrator) {
        return $true
    }

    Write-Warning 'sshuttle native Windows support must run from an Administrator PowerShell session.'
    if (-not (Confirm-Action -Message 'Relaunch this script in an elevated PowerShell session?')) {
        throw 'Administrator privileges are required to run sshuttle on Windows.'
    }

    Start-ElevatedPowerShell -RequestedSSHLocation $SSHLocation -RequestedKey $Key `
        -RequestedVerbose:($VerbosePreference -eq 'Continue')
    return $false
}

function Find-VirtualEnvironment {
    param([Parameter(Mandatory)] [string] $Directory)

    foreach ($name in @('.venv', 'venv', 'env')) {
        $candidate = Join-Path $Directory $name
        if ((Test-Path (Join-Path $candidate 'pyvenv.cfg') -PathType Leaf) -and
            (Test-Path (Join-Path $candidate 'Scripts\python.exe') -PathType Leaf)) {
            return $candidate
        }
    }

    return $null
}

function Enable-VirtualEnvironment {
    param([Parameter(Mandatory)] [string] $Path)

    $scriptsDirectory = Join-Path $Path 'Scripts'
    $env:VIRTUAL_ENV = [IO.Path]::GetFullPath($Path)
    Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
    Add-DirectoryToPath -Directory $scriptsDirectory
}

function New-PythonVirtualEnvironment {
    param(
        [Parameter(Mandatory)] [string] $PythonPath,
        [Parameter(Mandatory)] [string] $EnvironmentPath
    )

    Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'venv', '--help')
    & $PythonPath -m venv --help *> $null
    if ($LASTEXITCODE -eq 0) {
        Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'venv', $EnvironmentPath)
        & $PythonPath -m venv $EnvironmentPath | Out-Host
    }
    else {
        Write-Warning "Python at '$PythonPath' does not include the venv module; attempting to use virtualenv instead."
        Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'virtualenv', '--version')
        & $PythonPath -m virtualenv --version *> $null
        if ($LASTEXITCODE -ne 0) {
            Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'pip', '--version')
            & $PythonPath -m pip --version *> $null
            if ($LASTEXITCODE -ne 0) {
                Write-Host 'Bootstrapping pip with ensurepip...'
                Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'ensurepip', '--upgrade')
                & $PythonPath -m ensurepip --upgrade | Out-Host
                if ($LASTEXITCODE -ne 0) {
                    throw "Python at '$PythonPath' includes neither venv nor pip/ensurepip. Install a standard Python 3.10 or newer distribution with pip and venv, then ensure it is first on PATH."
                }
            }

            Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'pip', 'install', 'virtualenv')
            & $PythonPath -m pip install virtualenv | Out-Host
            if ($LASTEXITCODE -ne 0) {
                throw "Failed to install virtualenv using '$PythonPath'."
            }
        }

        Write-CommandPreview -FilePath $PythonPath -ArgumentList @('-m', 'virtualenv', $EnvironmentPath)
        & $PythonPath -m virtualenv $EnvironmentPath | Out-Host
    }

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the Python virtual environment at '$EnvironmentPath'."
    }
}

function Install-Sshuttle {
    param(
        [Parameter(Mandatory)] [string] $PythonPath,
        [Parameter(Mandatory)] [string] $EnvironmentPath
    )

    $environmentPython = Join-Path $EnvironmentPath 'Scripts\python.exe'
    if (-not (Test-Path $EnvironmentPath -PathType Container)) {
        New-PythonVirtualEnvironment -PythonPath $PythonPath -EnvironmentPath $EnvironmentPath
    }
    elseif (-not (Test-Path $environmentPython -PathType Leaf)) {
        throw "'$EnvironmentPath' already exists but is not a valid Windows Python virtual environment."
    }
    Enable-VirtualEnvironment -Path $EnvironmentPath
    Write-CommandPreview -FilePath $environmentPython -ArgumentList @('-m', 'pip', 'install', 'sshuttle')
    & $environmentPython -m pip install sshuttle | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install sshuttle in '$EnvironmentPath'."
    }
}

function Ensure-Sshuttle {
    param(
        [Parameter(Mandatory)] [string] $PythonPath,
        [Parameter(Mandatory)] [string] $WorkingDirectory
    )

    $sshuttlePath = Get-ApplicationPath -Name 'sshuttle.exe'
    if ($sshuttlePath) {
        return $sshuttlePath
    }

    $environmentPath = Find-VirtualEnvironment -Directory $WorkingDirectory
    if ($environmentPath) {
        Enable-VirtualEnvironment -Path $environmentPath
        $sshuttlePath = Get-ApplicationPath -Name 'sshuttle.exe'
        if ($sshuttlePath) {
            return $sshuttlePath
        }

        if (-not (Confirm-Action -Message "Install sshuttle in the existing virtual environment '$environmentPath'?")) {
            throw 'sshuttle.exe is required and was not found on PATH.'
        }
    }
    else {
        $environmentPath = Join-Path $WorkingDirectory '.venv'
        if (-not (Confirm-Action -Message "No existing sshuttle or Python virtual env found. Create virtual env '$environmentPath' and install sshuttle?")) {
            throw 'sshuttle.exe is required and was not found on PATH.'
        }
    }

    Install-Sshuttle -PythonPath $PythonPath -EnvironmentPath $environmentPath
    $sshuttlePath = Get-ApplicationPath -Name 'sshuttle.exe'
    if (-not $sshuttlePath) {
        throw "sshuttle installation completed, but sshuttle.exe was not found in '$environmentPath\Scripts'."
    }

    return $sshuttlePath
}

function Resolve-RequestedSSH {
    param([Parameter(Mandatory)] [string] $Location)

    $candidate = $Location
    if (Test-Path $candidate -PathType Container) {
        $candidate = Join-Path $candidate 'ssh.exe'
    }
    if (-not (Test-Path $candidate -PathType Leaf)) {
        throw "The SSH location '$Location' does not contain ssh.exe."
    }

    return (Resolve-Path $candidate).ProviderPath
}

function Find-SSHFromGit {
    $gitPath = Get-ApplicationPath -Name 'git.exe'
    if ($gitPath) {
        $gitSSH = Join-Path (Split-Path $gitPath -Parent) '..\usr\bin\ssh.exe'
        if (Test-Path $gitSSH -PathType Leaf) {
            return (Resolve-Path $gitSSH).ProviderPath
        }
    }

    $installRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ }
    foreach ($installRoot in $installRoots) {
        $gitSSH = Join-Path $installRoot 'Git\usr\bin\ssh.exe'
        if (Test-Path $gitSSH -PathType Leaf) {
            return (Resolve-Path $gitSSH).ProviderPath
        }
    }

    return $null
}

function Find-WindowsOpenSSH {
    $sshPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    if (Test-Path $sshPath -PathType Leaf) {
        return (Resolve-Path $sshPath).ProviderPath
    }

    return $null
}

function Install-WindowsOpenSSHClient {
    $capabilityName = 'OpenSSH.Client~~~~0.0.1.0'
    Write-Host 'Installing the Microsoft OpenSSH Client Windows capability...'
    Write-Verbose "Executing: Add-WindowsCapability -Online -Name $capabilityName"
    Add-WindowsCapability -Online -Name $capabilityName | Out-Host

    $sshPath = Find-WindowsOpenSSH
    if (-not $sshPath) {
        $expectedPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
        throw "The '$capabilityName' capability installation completed, but ssh.exe was not found at '$expectedPath'."
    }

    Add-DirectoryToPath -Directory (Split-Path $sshPath -Parent)
    return (Resolve-Path $sshPath).ProviderPath
}

function Ensure-SSH {
    param([string] $RequestedLocation, [switch] $PreferGit)

    if ($RequestedLocation) {
        $sshPath = Resolve-RequestedSSH -Location $RequestedLocation
        Add-DirectoryToPath -Directory (Split-Path $sshPath -Parent)
        return $sshPath
    }

    $sshPath = Get-ApplicationPath -Name 'ssh.exe'
    if (-not $sshPath) {
        if ($PreferGit) {
            $sshPath = Find-SSHFromGit
            if (-not $sshPath) {
                $sshPath = Find-WindowsOpenSSH
            }
        }
        else {
            $sshPath = Find-WindowsOpenSSH
            if (-not $sshPath) {
                $sshPath = Find-SSHFromGit
            }
        }
        if ($sshPath) {
            Add-DirectoryToPath -Directory (Split-Path $sshPath -Parent)
        }
    }

    if (-not $sshPath) {
        if (Confirm-Action -Message 'Install the Microsoft OpenSSH Client Windows feature now?') {
            $sshPath = Install-WindowsOpenSSHClient
        }
        else {
            throw 'ssh.exe is required. Install Windows OpenSSH or Git for Windows, or pass -SSHLocation with the path to ssh.exe.'
        }
    }

    return $sshPath
}

function Get-SSHUtility {
    param(
        [Parameter(Mandatory)] [string] $SSHPath,
        [Parameter(Mandatory)] [string] $Name
    )

    $siblingPath = Join-Path (Split-Path $SSHPath -Parent) $Name
    if (Test-Path $siblingPath -PathType Leaf) {
        return $siblingPath
    }

    return (Get-ApplicationPath -Name $Name)
}

function Get-SSHVersion {
    param([Parameter(Mandatory)] [string] $SSHPath)
    $result = Invoke-NativeProcess -FilePath $SSHPath -ArgumentList @('-V') -TimeoutSeconds 5
    $versionOutput = "$($result.StandardOutput)`n$($result.StandardError)".Trim()
    if (-not $result.Completed) {
        Write-Verbose "SSH version probe timed out for '$SSHPath'; falling back to executable location detection."
        return $null
    }
    if (-not $versionOutput) {
        Write-Verbose "SSH version probe returned no output (exit code $($result.ExitCode)); falling back to executable location detection."
        return $null
    }
    if ($null -ne $result.ExitCode -and $result.ExitCode -ne 0) {
        Write-Verbose "SSH version probe returned exit code $($result.ExitCode), but supplied usable version output."
    }
    return $versionOutput
}

function Test-SSHAgent {
    param([Parameter(Mandatory)] [string] $SSHAddPath)

    $windowsSSHAddPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-add.exe'
    $isWindowsSSHAdd = (Test-Path $windowsSSHAddPath -PathType Leaf) -and
        ([IO.Path]::GetFullPath($SSHAddPath) -eq [IO.Path]::GetFullPath($windowsSSHAddPath))
    $authenticationSocket = [Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK')
    if (-not $isWindowsSSHAdd -and -not $authenticationSocket) {
        Write-Verbose 'SSH_AUTH_SOCK is not set; skipping the standalone ssh-add agent probe.'
        return $false
    }
    $result = Invoke-NativeProcess -FilePath $SSHAddPath -ArgumentList @('-l') -TimeoutSeconds 5
    if (-not $result.Completed) {
        Write-Verbose 'ssh-add agent probe timed out after 5 seconds.'
        return $false
    }
    $probeOutput = "$($result.StandardOutput)`n$($result.StandardError)".Trim()
    $connectionError = 'error connecting to agent|could not open a connection|no such file or directory|connection refused|communication with agent failed'
    if ($probeOutput -match $connectionError) {
        Write-Verbose "The configured SSH authentication socket is not responding: $probeOutput"
        return $false
    }
    if ($null -ne $result.ExitCode) {
        return ($result.ExitCode -eq 0 -or
            ($result.ExitCode -eq 1 -and $probeOutput -match 'agent has no identities'))
    }

    return [bool] $probeOutput
}

function Start-SSHAgent {
    param(
        [Parameter(Mandatory)] [string] $SSHPath,
        [Parameter(Mandatory)] [string] $SSHAddPath
    )

    $agentPath = Get-SSHUtility -SSHPath $SSHPath -Name 'ssh-agent.exe'
    if (-not $agentPath) {
        throw 'ssh-agent.exe is required when -Key is specified.'
    }

    $sshVersion = Get-SSHVersion -SSHPath $SSHPath
    $windowsSSHPath = Find-WindowsOpenSSH
    $windowsAgentPath = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-agent.exe'
    $isWindowsAgent = $sshVersion -match 'OpenSSH_for_Windows'
    if (-not $isWindowsAgent -and $windowsSSHPath) {
        $isWindowsAgent = [IO.Path]::GetFullPath($SSHPath) -eq [IO.Path]::GetFullPath($windowsSSHPath)
    }
    if (-not $isWindowsAgent -and (Test-Path $windowsAgentPath -PathType Leaf)) {
        $isWindowsAgent = [IO.Path]::GetFullPath($agentPath) -eq [IO.Path]::GetFullPath($windowsAgentPath)
    }

    $detectionDetails = if ($sshVersion) { $sshVersion } else { "executable path '$SSHPath'" }
    if ($isWindowsAgent) {
        Write-Verbose "Detected Microsoft OpenSSH from $detectionDetails"
        try {
            Write-Verbose 'Executing: Set-Service -Name ssh-agent -StartupType Manual'
            Set-Service -Name 'ssh-agent' -StartupType Manual -ErrorAction Stop
            $service = Get-Service -Name 'ssh-agent' -ErrorAction Stop
            if ($service.Status -ne 'Running') {
                Write-Verbose 'Executing: Start-Service -Name ssh-agent'
                Start-Service -Name 'ssh-agent' -ErrorAction Stop
            }
        }
        catch {
            throw "Failed to enable and start the Microsoft OpenSSH Authentication Agent service: $_"
        }

        if (-not (Test-SSHAgent -SSHAddPath $SSHAddPath)) {
            throw 'The Microsoft OpenSSH Authentication Agent service started but ssh-add could not connect to it.'
        }
        return
    }

    Write-Verbose "Detected standalone SSH agent support from $detectionDetails"
    $result = Invoke-NativeProcess -FilePath $agentPath -ArgumentList @('-s') -TimeoutSeconds 10
    $agentOutput = "$($result.StandardOutput)`n$($result.StandardError)".Trim()
    if (-not $result.Completed) {
        Write-Verbose 'ssh-agent did not exit within 10 seconds; checking whether it initialized the agent before timing out.'
    }

    $socketMatch = [regex]::Match($agentOutput, 'SSH_AUTH_SOCK=([^;\r\n]+)')
    $pidMatch = [regex]::Match($agentOutput, 'SSH_AGENT_PID=([^;\r\n]+)')
    $agentInitialized = $socketMatch.Success -and $pidMatch.Success
    if ($socketMatch.Success) {
        $env:SSH_AUTH_SOCK = $socketMatch.Groups[1].Value.Trim('"')
    }
    if ($pidMatch.Success) {
        $env:SSH_AGENT_PID = $pidMatch.Groups[1].Value.Trim('"')
    }

    $knownFailure = $result.Completed -and $null -ne $result.ExitCode -and $result.ExitCode -ne 0
    if ($knownFailure -and -not $agentInitialized) {
        throw "Failed to launch ssh-agent.exe. $agentOutput"
    }
    if (-not $agentInitialized) {
        throw "ssh-agent.exe did not return SSH_AUTH_SOCK and SSH_AGENT_PID. $agentOutput"
    }

    if (-not (Test-SSHAgent -SSHAddPath $SSHAddPath)) {
        throw "Failed to connect to the launched ssh-agent.exe. $agentOutput"
    }
}

function Add-SSHKey {
    param(
        [Parameter(Mandatory)] [string] $KeyPath,
        [Parameter(Mandatory)] [string] $SSHPath
    )

    if (-not (Test-Path $KeyPath -PathType Leaf)) {
        throw "The SSH private key '$KeyPath' does not exist."
    }
    $resolvedKeyPath = (Resolve-Path $KeyPath).ProviderPath

    $sshAddPath = Get-SSHUtility -SSHPath $SSHPath -Name 'ssh-add.exe'
    if (-not $sshAddPath) {
        throw 'ssh-add.exe is required when -Key is specified.'
    }
    if (-not (Test-SSHAgent -SSHAddPath $sshAddPath)) {
        if ($env:SSH_AUTH_SOCK -or $env:SSH_AGENT_PID) {
            Write-Verbose 'Clearing stale SSH_AUTH_SOCK and SSH_AGENT_PID values.'
            Remove-Item Env:SSH_AUTH_SOCK, Env:SSH_AGENT_PID -ErrorAction SilentlyContinue
        }
        Start-SSHAgent -SSHPath $SSHPath -SSHAddPath $sshAddPath
    }

    Write-CommandPreview -FilePath $sshAddPath -ArgumentList @($resolvedKeyPath)
    & $sshAddPath $resolvedKeyPath
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add the SSH private key '$resolvedKeyPath' to ssh-agent."
    }

    $listResult = Invoke-NativeProcess -FilePath $sshAddPath -ArgumentList @('-l') -TimeoutSeconds 5
    $listOutput = "$($listResult.StandardOutput)`n$($listResult.StandardError)".Trim()
    if (-not $listResult.Completed) {
        throw 'Timed out while listing identities from ssh-agent.'
    }
    if ($null -ne $listResult.ExitCode -and $listResult.ExitCode -ne 0) {
        throw "Failed to list identities from ssh-agent. $listOutput"
    }
    if (-not $listOutput) {
        throw 'ssh-add reported success, but ssh-agent returned no identities.'
    }

    Write-Host 'SSH identities loaded in the agent:'
    Write-Host $listOutput
}

$pythonPath = Get-SupportedPython
if (-not (Ensure-Administrator)) {
    return
}

$workingDirectory = (Get-Location).ProviderPath
$sshuttlePath = Ensure-Sshuttle -PythonPath $pythonPath -WorkingDirectory $workingDirectory
$sshPath = Ensure-SSH -RequestedLocation $SSHLocation -PreferGit:([bool] $Key)

if ($Key) {
    Add-SSHKey -KeyPath $Key -SSHPath $sshPath
}

Write-Host "Ready: sshuttle=$sshuttlePath; ssh=$sshPath  use it like: sshuttle.exe -r user@host 192.168.0.0/16" -ForegroundColor Green
