[CmdletBinding()]
param(
    [ValidateSet('doctor','check','test','release','desktop','package')]
    [string]$Action = 'check',
    [string]$RustToolsRoot = $env:WATCH_UNLOCK_TOOL_ROOT,
    [string]$ResourceToolsRoot = $env:WATCH_UNLOCK_RESOURCE_TOOLS,
    [string]$RustToolchain = $env:WATCH_UNLOCK_RUST_TOOLCHAIN,
    # Gitee mirror "owner/repo"; package also writes updates/latest-gitee.json for it. '' skips it.
    [string]$GiteeRepo = $(if ($env:WATCH_UNLOCK_GITEE_REPO) { $env:WATCH_UNLOCK_GITEE_REPO } else { 'why_y1/watch-unlock-windows' })
)

$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$savedEnvironment = @{}
foreach ($name in @('PATH','CARGO_HOME','RUSTUP_HOME','RUSTFLAGS','CARGO_ENCODED_RUSTFLAGS',
    'CARGO_TARGET_DIR','CARGO_BUILD_TARGET','CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER',
    'CC_x86_64_pc_windows_gnu','RC_x86_64_pc_windows_gnu','npm_config_cache','RUSTUP_TOOLCHAIN',
    'TAURI_SIGNING_PRIVATE_KEY','TAURI_SIGNING_PRIVATE_KEY_PASSWORD')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$logRoot = Join-Path $projectRoot 'artifacts/build'
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$buildLogPath = Join-Path $logRoot ("{0}-{1}-{2}.log" -f (Get-Date -Format 'yyyyMMdd-HHmmss'),$Action,$PID)

function Invoke-Checked {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )

    $command = "$Executable $($Arguments -join ' ')"

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Directory: $(Get-Location)"
    Write-Host "Command:   $command"
    Write-Host "========================================" -ForegroundColor Cyan

    if (-not (Get-Command $Executable -ErrorAction SilentlyContinue)) { throw "Build executable not found: $Executable" }
    Add-Content -LiteralPath $buildLogPath -Value "`nDirectory: $(Get-Location)`nCommand: $command" -Encoding UTF8
    $savedPreference = $ErrorActionPreference
    try {
        # Windows PowerShell represents native stderr as error records even on success.
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath $buildLogPath -Append | Out-Host
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }

    if ($exitCode -ne 0) {
        Write-Host ""
        Write-Host "BUILD FAILED" -ForegroundColor Red
        Write-Host "Directory: $(Get-Location)" -ForegroundColor Red
        Write-Host "Command:   $command" -ForegroundColor Red
        Write-Host "Exit Code: $exitCode" -ForegroundColor Red
        Write-Host "Log:       $buildLogPath" -ForegroundColor Red

        throw "Build step failed (exit code $exitCode)"
    }

    Write-Host "BUILD STEP SUCCEEDED" -ForegroundColor Green
}

function Invoke-Core {
    param([ValidateSet('check','test','release')][string]$BuildAction)
    foreach ($directory in @('backend')) {
        Push-Location (Join-Path $projectRoot $directory)
        try {
            $cargoAction = if ($BuildAction -eq 'release') { 'build' } else { $BuildAction }
            if ($directory -eq 'backend' -and $BuildAction -eq 'test') {
                Invoke-Checked $cargoCommand ($toolchainArguments + @('build','--locked','-p','watch-unlock-provider'))
            }
            $arguments = $toolchainArguments + @($cargoAction,'--locked')
            if ($directory -eq 'backend') { $arguments += '--workspace' }
            if ($BuildAction -eq 'release') { $arguments += '--release' }
            Invoke-Checked $cargoCommand $arguments
        } finally { Pop-Location }
    }
}

function Invoke-Desktop {
    param([switch]$DependenciesReady, [switch]$SkipRelease)
    Push-Location (Join-Path $projectRoot 'apps/desktop')
    try {
        if (-not $DependenciesReady) { Invoke-Checked 'npm.cmd' @('ci','--ignore-scripts','--no-audit','--no-fund') }
        Invoke-Checked 'npm.cmd' @('run','build')
        $testRoot = Join-Path $projectRoot 'artifacts/frontend-tests'
        New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
        Invoke-Checked 'node.exe' @('node_modules/typescript/bin/tsc','src/validation.ts','--outDir',$testRoot,
            '--target','ES2022','--module','ES2022','--strict','--skipLibCheck')
        Copy-Item -LiteralPath (Join-Path $testRoot 'validation.js') -Destination (Join-Path $testRoot 'validation.mjs') -Force
        $testSource = [IO.File]::ReadAllText((Join-Path (Get-Location) 'src/validation.test.mjs'))
        if (-not $testSource.Contains('"./validation.ts"')) { throw 'Frontend test import changed; update the build test adapter.' }
        [IO.File]::WriteAllText((Join-Path $testRoot 'validation.test.mjs'),$testSource.Replace('"./validation.ts"','"./validation.mjs"'))
        Invoke-Checked 'node.exe' @('--test',(Join-Path $testRoot 'validation.test.mjs'))
        Push-Location 'src-tauri'
        try {
            Invoke-Checked $cargoCommand ($toolchainArguments + @('test','--locked'))
            if (-not $SkipRelease) {
                Invoke-Checked $cargoCommand ($toolchainArguments + @('build','--release','--locked','--features','custom-protocol'))
            }
        } finally { Pop-Location }
    } finally { Pop-Location }
}

function Initialize-BuildToolchain {
    if (-not $RustToolsRoot -and (Test-Path -LiteralPath (Join-Path $projectRoot '.tools/cargo/bin/cargo.exe'))) {
        $script:RustToolsRoot = Join-Path $projectRoot '.tools'
    }
    $script:cargoCommand = 'cargo'
    $script:toolchainArguments = @()
    if ($RustToolsRoot) {
        $resolvedTools = (Resolve-Path -LiteralPath $RustToolsRoot).Path
        $env:CARGO_HOME = Join-Path $resolvedTools 'cargo'
        $env:RUSTUP_HOME = Join-Path $resolvedTools 'rustup'
        $script:cargoCommand = Join-Path $env:CARGO_HOME 'bin/cargo.exe'
        if (-not $RustToolchain) { $script:RustToolchain = '1.90.0-x86_64-pc-windows-gnu' }
        $env:PATH = "$(Join-Path $env:CARGO_HOME 'bin');$env:PATH"
    }
    # `tauri build` invokes plain cargo; the rustup proxy honours this.
    if ($RustToolchain) { $script:toolchainArguments = @("+$RustToolchain"); $env:RUSTUP_TOOLCHAIN = $RustToolchain }
    if (-not (Get-Command $cargoCommand -ErrorAction SilentlyContinue)) {
        throw 'Cargo is missing. Supply -RustToolsRoot or use a configured Rust terminal.'
    }
    $rustc = if ($RustToolsRoot) { Join-Path $env:CARGO_HOME 'bin/rustc.exe' } else { 'rustc' }
    $rustVersion = @(& $rustc @toolchainArguments -vV)
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the selected Rust toolchain.' }
    $script:rustHost = ($rustVersion | Where-Object { $_ -like 'host: *' }) -replace '^host: ',''
    if ($rustHost -notin @('x86_64-pc-windows-gnu','x86_64-pc-windows-msvc')) {
        throw 'Use an x86_64 Windows Rust toolchain for this Credential Provider and desktop package.'
    }
    # Keep predictable per-workspace outputs, restoring all environment values on exit.
    $env:CARGO_TARGET_DIR = $null
    $env:CARGO_BUILD_TARGET = $null
    if ($rustHost -eq 'x86_64-pc-windows-gnu') {
        $sysroot = & $rustc @toolchainArguments --print sysroot
        if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the selected Rust sysroot.' }
        $rustBin = Join-Path $sysroot 'lib/rustlib/x86_64-pc-windows-gnu/bin'
        $linker = Join-Path $rustBin 'self-contained/x86_64-w64-mingw32-gcc.exe'
        if (-not (Test-Path -LiteralPath $linker -PathType Leaf)) { throw 'Rust self-contained GNU linker is missing.' }
        $binutils = if ($RustToolsRoot) { Join-Path $resolvedTools 'msys-binutils/mingw64/bin' } else { '' }
        if ($binutils -and (Test-Path -LiteralPath $binutils)) { $env:PATH = "$binutils;$env:PATH" }
        $env:PATH = "$rustBin;$env:PATH"
        $dlltoolCommand = Get-Command dlltool.exe -ErrorAction SilentlyContinue
        if (-not $dlltoolCommand -and $ResourceToolsRoot) {
            $dlltoolCandidate = Join-Path $ResourceToolsRoot 'bin/x86_64-w64-mingw32-dlltool.exe'
            if (Test-Path -LiteralPath $dlltoolCandidate) { $dlltoolCommand = Get-Command $dlltoolCandidate }
        }
        if (-not $dlltoolCommand) { throw 'GNU dlltool is missing. Supply MinGW binutils or -ResourceToolsRoot.' }
        $env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = $linker
        $flags = if ($env:CARGO_ENCODED_RUSTFLAGS) { $env:CARGO_ENCODED_RUSTFLAGS -split [char]31 }
                 elseif ($env:RUSTFLAGS) { $env:RUSTFLAGS -split '\s+' } else { @() }
        $env:CARGO_ENCODED_RUSTFLAGS = (@($flags) + @('-C','link-self-contained=yes','-C',"dlltool=$($dlltoolCommand.Source)")) -join [char]31
        $env:RUSTFLAGS = $null
        if ($ResourceToolsRoot) {
            $resourceBin = Join-Path (Resolve-Path -LiteralPath $ResourceToolsRoot).Path 'bin'
            $env:PATH = "$resourceBin;$env:PATH"
            $env:CC_x86_64_pc_windows_gnu = Join-Path $resourceBin 'x86_64-w64-mingw32-gcc.exe'
            $env:RC_x86_64_pc_windows_gnu = Join-Path $resourceBin 'windres.exe'
        }
    }
    Write-Output "Selected Rust host: $rustHost"
}

function Test-DesktopTools {
    if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) { throw 'Node.js and npm are required for desktop builds.' }
    $nodeVersion = & node.exe -p 'process.versions.node'
    if ($LASTEXITCODE -ne 0 -or -not (([version]$nodeVersion -ge [version]'20.19.0' -and
        [version]$nodeVersion -lt [version]'21.0.0') -or [version]$nodeVersion -ge [version]'22.12.0')) {
        throw 'Use Node.js 20.19+ or 22.12+ for the desktop frontend.'
    }
    if ($rustHost -eq 'x86_64-pc-windows-gnu') {
        $resourceCompiler = Get-Command windres.exe -ErrorAction SilentlyContinue
        if (-not $resourceCompiler) { throw 'A complete MinGW toolchain is required. Supply -ResourceToolsRoot.' }
        $probeSource = Join-Path $logRoot 'resource-probe.rc'
        $probeOutput = Join-Path $logRoot 'resource-probe.o'
        Set-Content -LiteralPath $probeSource -Value '1 RCDATA { 1 }' -Encoding Ascii
        try { Invoke-Checked $resourceCompiler.Source @('-i',$probeSource,'-o',$probeOutput,'-O','coff') }
        catch { throw 'Resource compilation failed. Supply a complete LLVM-MinGW or MinGW root with windres and its C preprocessor. See artifacts/build for the command and log.' }
    }
}

function Set-UpdaterSigningKey {
    # Update packages must be signed, or installed copies refuse them. The private key comes from
    # the environment, or from the DPAPI-protected file this Windows account created with
    # `tauri signer generate`. It only ever lives in this process's environment.
    if ($env:TAURI_SIGNING_PRIVATE_KEY) { return }
    $keyFile = Join-Path $env:USERPROFILE '.watch-unlock\updater-key.dpapi'
    if (-not (Test-Path -LiteralPath $keyFile)) {
        throw "Updater signing key not found. Set TAURI_SIGNING_PRIVATE_KEY or restore $keyFile from your backup."
    }
    $secure = (Get-Content -LiteralPath $keyFile -Raw).Trim() | ConvertTo-SecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $env:TAURI_SIGNING_PRIVATE_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
    if ($null -eq $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD) { $env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = '' }
}

function Invoke-Installer {
    # `tauri build` compiles the release window with the embedded UI and wraps it, the backend
    # (bundle.resources) and the installer hooks into an NSIS setup.exe plus its update signature.
    # On first use it downloads the free NSIS toolset into Tauri's own cache.
    Set-UpdaterSigningKey
    Push-Location (Join-Path $projectRoot 'apps/desktop')
    try { Invoke-Checked 'npm.cmd' @('run','tauri','--','build','--bundles','nsis') }
    finally { Pop-Location }
}

function Get-ReleaseNotes([string]$Version) {
    # The `## <version>` section of CHANGELOG.md, without its heading.
    $lines = [IO.File]::ReadAllLines((Join-Path $projectRoot 'CHANGELOG.md'), [Text.Encoding]::UTF8)
    $start = [Array]::FindIndex($lines, [Predicate[string]]{ param($line) $line.Trim() -eq "## $Version" })
    if ($start -lt 0) { throw "CHANGELOG.md has no '## $Version' section; add the release notes first." }
    $section = foreach ($line in $lines[($start + 1)..($lines.Length - 1)]) {
        if ($line.StartsWith('## ')) { break }
        $line
    }
    ($section -join "`n").Trim()
}

function New-UpdateManifest([string]$Version, [string]$Notes, [string]$Signature, [string]$Url) {
    [ordered]@{
        version = $Version
        notes = $Notes
        pub_date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        platforms = [ordered]@{ 'windows-x86_64' = [ordered]@{ signature = $Signature; url = $Url } }
    } | ConvertTo-Json -Depth 4
}

function New-ReleasePackage {
    & (Join-Path $projectRoot 'scripts/Check-Release.ps1')
    $version = ([IO.File]::ReadAllText((Join-Path $projectRoot 'apps/desktop/src-tauri/tauri.conf.json')) | ConvertFrom-Json).version
    $notes = Get-ReleaseNotes $version
    $bundle = Join-Path $projectRoot 'apps/desktop/src-tauri/target/release/bundle/nsis'
    $setup = Get-Item -LiteralPath (Join-Path $bundle "Watch Unlock_${version}_x64-setup.exe")
    $signature = Get-Item -LiteralPath "$($setup.FullName).sig"
    $distRoot = [IO.Path]::GetFullPath((Join-Path $projectRoot 'dist'))
    if ((Test-Path -LiteralPath $distRoot) -and
        ((Get-Item -LiteralPath $distRoot -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'dist cannot be a junction or symbolic link.'
    }
    # Recreate only this output directory; stale files must not survive packaging.
    if (Test-Path -LiteralPath $distRoot) { Remove-Item -LiteralPath $distRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $distRoot | Out-Null
    # No spaces: GitHub would rename the asset, and the update manifest must name it exactly.
    $name = "WatchUnlock_${version}_x64-setup.exe"
    Copy-Item -LiteralPath $setup.FullName -Destination (Join-Path $distRoot $name)
    Copy-Item -LiteralPath $signature.FullName -Destination (Join-Path $distRoot "$name.sig")
    $signatureText = [IO.File]::ReadAllText($signature.FullName).Trim()
    $utf8 = New-Object Text.UTF8Encoding $false
    $githubUrl = "https://github.com/whyy1/watch-unlock-windows/releases/download/v$version/$name"
    [IO.File]::WriteAllText((Join-Path $distRoot 'latest.json'), (New-UpdateManifest $version $notes $signatureText $githubUrl), $utf8)
    if ($GiteeRepo) {
        # Gitee mirror: the manifest is served raw from the repository and points at its release.
        $giteeUrl = "https://gitee.com/$GiteeRepo/releases/download/v$version/$name"
        $giteeManifest = Join-Path $projectRoot 'updates/latest-gitee.json'
        New-Item -ItemType Directory -Path (Split-Path -Parent $giteeManifest) -Force | Out-Null
        [IO.File]::WriteAllText($giteeManifest, (New-UpdateManifest $version $notes $signatureText $giteeUrl), $utf8)
    }
    $hash = (Get-FileHash -LiteralPath (Join-Path $distRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name" | Set-Content -LiteralPath (Join-Path $distRoot 'SHA256SUMS.txt') -Encoding ASCII
    Write-Output "Installer: dist/$name (version $version, signed for updates)"
}


try {
    $env:npm_config_cache = Join-Path $projectRoot 'artifacts/npm-cache'
    Initialize-BuildToolchain
    if ($Action -in @('doctor','desktop','package')) { Test-DesktopTools }
    if ($Action -eq 'doctor') {
        Invoke-Checked $cargoCommand ($toolchainArguments + @('--version'))
        Invoke-Checked 'node.exe' @('--version')
        Invoke-Checked 'npm.cmd' @('--version')
    } elseif ($Action -eq 'desktop') {
        Invoke-Desktop
    } elseif ($Action -eq 'package') {
        Push-Location (Join-Path $projectRoot 'apps/desktop')
        try { Invoke-Checked 'npm.cmd' @('ci','--ignore-scripts','--no-audit','--no-fund') }
        finally { Pop-Location }
        foreach ($directory in @('backend','apps/desktop/src-tauri')) {
            Push-Location (Join-Path $projectRoot $directory)
            try { Invoke-Checked $cargoCommand ($toolchainArguments + @('fetch','--locked','--target',$rustHost)) }
            finally { Pop-Location }
        }
        & (Join-Path $PSScriptRoot 'Export-ThirdPartyNotices.ps1') -RustToolsRoot $RustToolsRoot -RustToolchain $RustToolchain
        & (Join-Path $PSScriptRoot 'Check-Release.ps1')
        Invoke-Core 'test'
        Invoke-Core 'release'
        Invoke-Desktop -DependenciesReady -SkipRelease
        Invoke-Installer
        New-ReleasePackage
    } else {
        Invoke-Core $Action
    }
    Write-Output "Build log: $buildLogPath"
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        if ($null -eq $savedEnvironment[$name]) { Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process') }
    }
}
