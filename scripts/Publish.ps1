[CmdletBinding(SupportsShouldProcess)]
param(
    # Remotes that receive main and the release tag; a missing remote is skipped.
    [string[]]$Remotes = @('origin','gitee'),
    [string]$GitHubRepo = 'whyy1/watch-unlock-windows',
    # The Gitee mirror; its release is published when the 'gitee' remote is configured.
    [string]$GiteeRepo = 'why_y1/watch-unlock-windows'
)

# Publishes the package that `Build.ps1 -Action package` left in dist/: tags the current commit,
# pushes the tag, creates the GitHub and Gitee releases with the installer, its update signature,
# latest.json and SHA256SUMS, and pushes main last. The Gitee updater manifest is read from main,
# so it only goes live once its download exists. Re-running finishes a release that stopped halfway.
$ErrorActionPreference = 'Stop'
$projectRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

function Invoke-Native([string]$Executable, [string[]]$Arguments) {
    # git and gh report progress on stderr, which Windows PowerShell turns into errors.
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Executable @Arguments 2>&1 | ForEach-Object { $_.ToString() } | Out-Host
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($exitCode -ne 0) { throw "$Executable $($Arguments -join ' ') failed (exit code $exitCode)" }
}

function Get-GiteeToken {
    # A personal access token with the "projects" scope, from the environment or from the file this
    # Windows account wrote with DPAPI. It is only sent in request bodies, never on a command line.
    if ($env:WATCH_UNLOCK_GITEE_TOKEN) { return $env:WATCH_UNLOCK_GITEE_TOKEN }
    $tokenFile = Join-Path $env:USERPROFILE '.watch-unlock\gitee-token.dpapi'
    if (-not (Test-Path -LiteralPath $tokenFile)) {
        throw "Gitee token not found. Set WATCH_UNLOCK_GITEE_TOKEN or save it to $tokenFile (see docs/development.md)."
    }
    $secure = (Get-Content -LiteralPath $tokenFile -Raw).Trim() | ConvertTo-SecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function Invoke-Gitee([string]$Method, [string]$Path, [Net.Http.HttpContent]$Content) {
    $uri = "https://gitee.com/api/v5/repos/$GiteeRepo/$Path"
    # Gitee reads the token from the query for GET and for file uploads; a multipart field is ignored (401).
    if ($Method -eq 'GET' -or $Content -is [Net.Http.MultipartFormDataContent]) {
        $uri += "?access_token=$([Uri]::EscapeDataString($giteeToken))"
    }
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::new($Method), $uri)
    $request.Content = $Content
    $response = $http.SendAsync($request).GetAwaiter().GetResult()
    $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    if ($Method -eq 'GET' -and [int]$response.StatusCode -eq 404) { return $null }
    if (-not $response.IsSuccessStatusCode) { throw "Gitee $Method $Path failed ($([int]$response.StatusCode)): $text" }
    if ($text.Trim() -in @('', 'null')) { return $null }
    $text | ConvertFrom-Json
}

function New-GiteeForm([hashtable]$Fields) {
    $Fields['access_token'] = $giteeToken
    $pairs = New-Object 'System.Collections.Generic.List[System.Collections.Generic.KeyValuePair[string,string]]'
    foreach ($key in $Fields.Keys) { $pairs.Add((New-Object 'System.Collections.Generic.KeyValuePair[string,string]' $key, $Fields[$key])) }
    [Net.Http.FormUrlEncodedContent]::new($pairs)
}

function Publish-GiteeRelease([string]$Tag, [string]$Title, [string]$Notes, [string[]]$Files, [string]$InstallerUrl) {
    $release = Invoke-Gitee 'GET' "releases/tags/$Tag"
    if (-not $release -or -not $release.id) {
        $release = Invoke-Gitee 'POST' 'releases' (New-GiteeForm @{
            tag_name = $Tag; name = $Title; body = $Notes; prerelease = 'false'; target_commitish = 'main' })
    }
    $attached = @{}
    foreach ($file in (Invoke-Gitee 'GET' "releases/$($release.id)/attach_files")) { $attached[$file.name] = $file.browser_download_url }
    foreach ($path in $Files) {
        $name = Split-Path -Leaf $path
        if ($attached.ContainsKey($name)) { continue }
        $form = New-Object Net.Http.MultipartFormDataContent
        $form.Add((New-Object Net.Http.StringContent $giteeToken), 'access_token')
        $stream = [IO.File]::OpenRead($path)
        try {
            $body = New-Object Net.Http.StreamContent $stream
            $body.Headers.ContentType = [Net.Http.Headers.MediaTypeHeaderValue]::Parse('application/octet-stream')
            $form.Add($body, 'file', $name)
            $uploaded = Invoke-Gitee 'POST' "releases/$($release.id)/attach_files" $form
        } finally { $stream.Dispose(); $form.Dispose() }
        $attached[$name] = $uploaded.browser_download_url
        Write-Output "Gitee: attached $name"
    }
    # updates/latest-gitee.json promises this exact URL; stop before main makes that promise public.
    $installer = $attached[(Split-Path -Leaf $Files[0])]
    if ($installer -ne $InstallerUrl) { throw "Gitee serves the installer at '$installer', but updates/latest-gitee.json points at '$InstallerUrl'." }
}

Push-Location $projectRoot
try {
    $version = ([IO.File]::ReadAllText((Join-Path $projectRoot 'apps/desktop/src-tauri/tauri.conf.json')) | ConvertFrom-Json).version
    $tag = "v$version"
    $title = "Watch Unlock $version"
    $name = "WatchUnlock_${version}_x64-setup.exe"
    $dist = Join-Path $projectRoot 'dist'
    $assets = @($name, "$name.sig", 'latest.json', 'SHA256SUMS.txt') | ForEach-Object { Join-Path $dist $_ }
    foreach ($asset in $assets) {
        if (-not (Test-Path -LiteralPath $asset -PathType Leaf)) { throw "Missing $asset; run Build.ps1 -Action package first." }
    }
    $manifest = [IO.File]::ReadAllText((Join-Path $dist 'latest.json')) | ConvertFrom-Json
    if ($manifest.version -ne $version) { throw "dist/latest.json is for $($manifest.version), not $version; rebuild the package." }

    if ((git branch --show-current) -ne 'main') { throw 'Publish from main.' }
    if (git status --porcelain) { throw 'The working tree has uncommitted changes; commit them first.' }
    $known = @(git remote)
    $pushRemotes = @($Remotes | Where-Object { $known -contains $_ })
    foreach ($remote in $Remotes) { if ($known -notcontains $remote) { Write-Warning "Remote '$remote' not configured; skipped." } }
    $useGitee = $pushRemotes -contains 'gitee'
    if ($useGitee) {
        $giteeManifestPath = Join-Path $projectRoot 'updates/latest-gitee.json'
        if (-not (Test-Path -LiteralPath $giteeManifestPath)) { throw 'updates/latest-gitee.json is missing; rebuild the package and commit it.' }
        $giteeManifest = [IO.File]::ReadAllText($giteeManifestPath) | ConvertFrom-Json
        $signature = $giteeManifest.platforms.'windows-x86_64'
        if ($giteeManifest.version -ne $version -or $signature.signature -ne $manifest.platforms.'windows-x86_64'.signature) {
            throw 'updates/latest-gitee.json does not match dist/; rebuild the package and commit it.'
        }
        $giteeToken = Get-GiteeToken
    }
    & (Join-Path $PSScriptRoot 'Check-Release.ps1')

    $notesFile = Join-Path ([IO.Path]::GetTempPath()) "watch-unlock-$tag-notes.md"
    [IO.File]::WriteAllText($notesFile, $manifest.notes, (New-Object Text.UTF8Encoding $false))
    try {
        if ($PSCmdlet.ShouldProcess($tag, 'tag, push and create the GitHub and Gitee releases')) {
            if (-not (git tag --list $tag)) { Invoke-Native 'git' @('tag', '-a', $tag, '-m', "Watch Unlock Windows $version") }
            foreach ($remote in $pushRemotes) { Invoke-Native 'git' @('push', $remote, $tag) }

            # "release not found" on stderr must not stop the script under ErrorActionPreference=Stop.
            $savedPreference = $ErrorActionPreference
            try {
                $ErrorActionPreference = 'Continue'
                & gh release view $tag --repo $GitHubRepo *> $null
                $releaseExists = $LASTEXITCODE -eq 0
            } finally { $ErrorActionPreference = $savedPreference }
            if ($releaseExists) { Write-Output "GitHub release $tag already exists; skipped." }
            else {
                Invoke-Native 'gh' (@('release', 'create', $tag, '--repo', $GitHubRepo, '--title', $title,
                    '--notes-file', $notesFile, '--verify-tag') + $assets)
            }

            if ($useGitee) {
                Add-Type -AssemblyName System.Net.Http
                [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                $http = New-Object Net.Http.HttpClient
                $http.Timeout = [TimeSpan]::FromMinutes(10)
                try { Publish-GiteeRelease $tag $title $manifest.notes $assets $signature.url }
                finally { $http.Dispose() }
            }

            foreach ($remote in $pushRemotes) { Invoke-Native 'git' @('push', $remote, 'main') }
            Write-Output "Published $tag."
        }
    } finally { Remove-Item -LiteralPath $notesFile -ErrorAction SilentlyContinue }
} finally {
    $giteeToken = $null
    Pop-Location
}
