# SPDX-License-Identifier: MIT OR Apache-2.0
# R-008 phase B: read-only cross-channel hash census (2026-10-22). Writes research/r-008/census.tsv and raw files under .research-local/r-008/census/.
# The optional read-only GitHub token is read from the ignored secrets file into a variable and sent only as a header.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$raw = 'D:\Projects\pakomichi\.research-local\r-008\census'
New-Item -ItemType Directory -Force $raw | Out-Null
$tokFile = 'D:\Projects\pakomichi\.research-local\r-003\secrets\github-token'
$script:tok = $null
$script:apiCalls = 0
$utf8 = New-Object Text.UTF8Encoding $false

function SafeName($s) { return ($s -replace '[^A-Za-z0-9._-]', '_') }

function Fetch([string]$url, [string]$file, [bool]$api = $false) {
  $h = @{ 'User-Agent' = 'pakomichi-r008-census' }
  if ($api) {
    $h['Accept'] = 'application/vnd.github+json'
    $h['X-GitHub-Api-Version'] = '2022-11-28'
    if ($script:tok) { $h['Authorization'] = 'Bearer ' + $script:tok }
    $script:apiCalls++
  }
  try {
    $r = Invoke-WebRequest -Uri $url -Headers $h -UseBasicParsing
  } catch {
    $code = 0
    if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
    if ($api -and ($code -eq 403 -or $code -eq 429) -and -not $script:tok) {
      $script:tok = (Get-Content -Raw $tokFile).Trim()
      return Fetch $url $file $api
    }
    [IO.File]::WriteAllText((Join-Path $raw ($file + '.err')), "$code $url`n", $utf8)
    return $null
  }
  if ($api) {
    $rem = $r.Headers['X-RateLimit-Remaining']
    if ($rem -and [int]$rem -lt 4 -and -not $script:tok) { $script:tok = (Get-Content -Raw $tokFile).Trim() }
  }
  $c = $r.Content
  if ($c -is [byte[]]) { $c = $utf8.GetString($c) }
  [IO.File]::WriteAllText((Join-Path $raw $file), $c, $utf8)
  return $c
}

$relCache = @{}
function Get-Release([string]$repo, [string]$tag) {
  $k = "$repo@$tag".ToLower()
  if ($relCache.ContainsKey($k)) { return $relCache[$k] }
  if ($tag -eq 'latest') { $u = "https://api.github.com/repos/$repo/releases/latest" }
  else { $u = "https://api.github.com/repos/$repo/releases/tags/" + [uri]::EscapeDataString($tag) }
  $c = Fetch $u ('gh_' + (SafeName "$repo@$tag") + '.json') $true
  $rel = $null
  if ($c) { $rel = $c | ConvertFrom-Json }
  $relCache[$k] = $rel
  if ($rel -and $tag -eq 'latest') { $relCache[("$repo@" + $rel.tag_name).ToLower()] = $rel }
  return $rel
}

$tools = @(
  @{t='ripgrep';  repo='BurntSushi/ripgrep';      wg='BurntSushi.ripgrep.MSVC'; sc='ripgrep';  br='ripgrep';   aur='ripgrep-bin'},
  @{t='fd';       repo='sharkdp/fd';              wg='sharkdp.fd';              sc='fd';       br='fd';        aur='fd-bin'},
  @{t='bat';      repo='sharkdp/bat';             wg='sharkdp.bat';             sc='bat';      br='bat';       aur='bat-bin'},
  @{t='fzf';      repo='junegunn/fzf';            wg='junegunn.fzf';            sc='fzf';      br='fzf';       aur='fzf-bin'},
  @{t='jq';       repo='jqlang/jq';               wg='jqlang.jq';               sc='jq';       br='jq';        aur='jq-bin'},
  @{t='yq';       repo='mikefarah/yq';            wg='MikeFarah.yq';            sc='yq';       br='yq';        aur='go-yq-bin'},
  @{t='gh';       repo='cli/cli';                 wg='GitHub.cli';              sc='gh';       br='gh';        aur='github-cli-bin'},
  @{t='lazygit';  repo='jesseduffield/lazygit';   wg='JesseDuffield.lazygit';   sc='lazygit';  br='lazygit';   aur='lazygit-bin'},
  @{t='delta';    repo='dandavison/delta';        wg='dandavison.delta';        sc='delta';    br='git-delta'; aur='git-delta-bin'},
  @{t='starship'; repo='starship/starship';       wg='Starship.Starship';       sc='starship'; br='starship';  aur='starship-bin'},
  @{t='zoxide';   repo='ajeetdsouza/zoxide';      wg='ajeetdsouza.zoxide';      sc='zoxide';   br='zoxide';    aur='zoxide-bin'},
  @{t='eza';      repo='eza-community/eza';       wg='eza-community.eza';       sc='eza';      br='eza';       aur='eza-bin'},
  @{t='hyperfine';repo='sharkdp/hyperfine';       wg='sharkdp.hyperfine';       sc='hyperfine';br='hyperfine'; aur='hyperfine-bin'},
  @{t='k9s';      repo='derailed/k9s';            wg='Derailed.k9s';            sc='k9s';      br='k9s';       aur='k9s-bin'},
  @{t='age';      repo='FiloSottile/age';         wg='FiloSottile.age';         sc='age';      br='age';       aur='age-bin'},
  @{t='sops';     repo='getsops/sops';            wg='Mozilla.SOPS';            sc='sops';     br='sops';      aur='sops-bin'},
  @{t='croc';     repo='schollz/croc';            wg='schollz.croc';            sc='croc';     br='croc';      aur='croc-bin'},
  @{t='just';     repo='casey/just';              wg='Casey.Just';              sc='just';     br='just';      aur='just-bin'}
)

$rows = New-Object System.Collections.ArrayList
function Norm([string]$h) { if (-not $h) { return '' } ; return ($h.Trim() -replace '^sha256:', '').ToLower() }

function Classify($tool, $rel, $channel, $cver, $curl, $chash, $extraNote) {
  $ver = $rel.tag_name -replace '^[^0-9]*', ''
  $u = ($curl -replace '#.*$', '').Trim()
  $result = 'not-comparable'; $asset = ''; $gd = ''; $note = $extraNote
  $lagged = ($cver -and $cver -ne $ver)
  if ($u -match '^https://github\.com/([^/]+/[^/]+)/releases/download/([^/]+)/(.+)$') {
    $urepo = $Matches[1]; $utag = [uri]::UnescapeDataString($Matches[2]); $uname = [uri]::UnescapeDataString($Matches[3])
    $r2 = Get-Release $urepo $utag
    $asset = $uname
    if (-not $r2) { $result = 'not-comparable'; $note = "$note; release $urepo@$utag not found via API".Trim('; ') }
    else {
      $a = $r2.assets | Where-Object { $_.name -eq $uname } | Select-Object -First 1
      if (-not $a) { $result = 'not-comparable'; $note = "$note; asset not in release $utag".Trim('; ') }
      elseif (-not $a.digest) { $result = 'no-github-digest'; $note = "$note; tag $utag".Trim('; ') }
      else {
        $gd = $a.digest
        $eq = ((Norm $a.digest) -eq (Norm $chash))
        if ($utag -eq $rel.tag_name) { if ($eq) { $result = 'match' } else { $result = 'mismatch' } }
        else {
          $result = 'lag'
          if ($eq) { $note = "$note; equals digest of $utag (release id $($r2.id), immutable=$($r2.immutable))".Trim('; ') }
          else { $note = "$note; MISMATCH vs digest of $utag".Trim('; ') }
        }
      }
    }
  } else {
    $name = ($u -split '/')[-1]
    $a = $rel.assets | Where-Object { $_.name -eq $name } | Select-Object -First 1
    if ($a) { $asset = $a.name; $gd = $a.digest; $note = "$note; same file name as latest asset; hash equal=$(((Norm $a.digest) -eq (Norm $chash)))".Trim('; ') }
    if ($lagged) { $note = "$note; catalog version differs".Trim('; ') }
  }
  [void]$rows.Add([pscustomobject]@{tool=$tool; github_repo_id=$rel.__repoid; tag=$rel.tag_name; release_immutable=$rel.immutable; asset=$asset; github_digest=$gd; channel=$channel; channel_version=$cver; channel_url=$curl; channel_hash=(Norm $chash); result=$result; note=$note})
}

$summary = @()
foreach ($T in $tools) {
  $rel = Get-Release $T.repo 'latest'
  if (-not $rel) { [void]$rows.Add([pscustomobject]@{tool=$T.t; github_repo_id=''; tag=''; release_immutable=''; asset=''; github_digest=''; channel='github'; channel_version=''; channel_url=''; channel_hash=''; result='error'; note='latest release not readable'}); continue }
  $repoId = ''
  if ($rel.url -match '/repositories/(\d+)/') { $repoId = $Matches[1] }
  if (-not $repoId) { $rc = Fetch "https://api.github.com/repos/$($T.repo)" ('ghrepo_' + (SafeName $T.repo) + '.json') $true; if ($rc) { $repoId = ($rc | ConvertFrom-Json).id } }
  $rel | Add-Member -NotePropertyName __repoid -NotePropertyValue $repoId -Force
  $ver = $rel.tag_name -replace '^[^0-9]*', ''
  $nd = @($rel.assets | Where-Object { $_.digest }).Count
  $summary += "$($T.t) repo=$repoId release=$($rel.id) tag=$($rel.tag_name) immutable=$($rel.immutable) published=$($rel.published_at) assets=$($rel.assets.Count) withDigest=$nd"

  # WinGet
  $parts = $T.wg.Split('.')
  $wpath = 'manifests/' + $T.wg.Substring(0,1).ToLower() + '/' + ($parts -join '/')
  $lst = Fetch "https://api.github.com/repos/microsoft/winget-pkgs/contents/$wpath" ('wg_' + (SafeName $T.wg) + '_dir.json') $true
  if (-not $lst) { Classify $T.t $rel 'winget' '' '' '' "manifest dir $wpath not found" }
  else {
    $vers = @(($lst | ConvertFrom-Json) | Where-Object { $_.type -eq 'dir' } | ForEach-Object { $_.name })
    $cv = $null
    if ($vers -contains $ver) { $cv = $ver } else {
      $cv = $vers | Sort-Object { $v = $null; $s = ($_ -replace '[^0-9.]', '').Trim('.'); if ([version]::TryParse($s, [ref]$v)) { $v } else { [version]'0.0' } } | Select-Object -Last 1
    }
    $y = Fetch "https://raw.githubusercontent.com/microsoft/winget-pkgs/master/$wpath/$cv/$($T.wg).installer.yaml" ('wg_' + (SafeName $T.wg) + "_$cv.installer.yaml")
    if (-not $y) { Classify $T.t $rel 'winget' $cv '' '' 'installer yaml not readable' }
    else {
      $us = [regex]::Matches($y, '(?m)^\s*-?\s*InstallerUrl:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value.Trim("'", '"') }
      $hs = [regex]::Matches($y, '(?m)^\s*-?\s*InstallerSha256:\s*(\S+)') | ForEach-Object { $_.Groups[1].Value.Trim("'", '"') }
      $us = @($us); $hs = @($hs)
      $n = [Math]::Min($us.Count, $hs.Count)
      $pn = ''; if ($us.Count -ne $hs.Count) { $pn = "url/hash count $($us.Count)/$($hs.Count)" }
      $seen = @{}
      for ($i = 0; $i -lt $n; $i++) { $k = $us[$i] + '|' + $hs[$i]; if ($seen[$k]) { continue }; $seen[$k] = 1; Classify $T.t $rel 'winget' $cv $us[$i] $hs[$i] $pn }
    }
  }

  # Scoop
  $sj = $null; $bucket = ''
  foreach ($b in 'Main', 'Extras') {
    $c = Fetch "https://raw.githubusercontent.com/ScoopInstaller/$b/master/bucket/$($T.sc).json" ("scoop_${b}_$($T.sc).json")
    if ($c) { $sj = $c | ConvertFrom-Json; $bucket = $b; break }
  }
  if (-not $sj) { Classify $T.t $rel 'scoop' '' '' '' 'not in Main or Extras' }
  else {
    $pairs = @()
    if ($sj.url) { $pairs += ,@($sj.url, $sj.hash, 'top') }
    if ($sj.architecture) {
      foreach ($p in $sj.architecture.PSObject.Properties) { if ($p.Value.url) { $pairs += ,@($p.Value.url, $p.Value.hash, $p.Name) } }
    }
    foreach ($pr in $pairs) {
      $ul = @($pr[0]); $hl = @($pr[1])
      for ($i = 0; $i -lt $ul.Count; $i++) { Classify $T.t $rel "scoop-$($bucket.ToLower())" $sj.version $ul[$i] $hl[$i] $pr[2] }
    }
  }

  # Homebrew
  $bj = Fetch "https://formulae.brew.sh/api/formula/$($T.br).json" ("brew_formula_$($T.br).json")
  if ($bj) {
    $f = $bj | ConvertFrom-Json
    Classify $T.t $rel 'homebrew-formula' $f.versions.stable $f.urls.stable.url $f.urls.stable.checksum 'source url; bottles not compared'
  } else {
    $cj = Fetch "https://formulae.brew.sh/api/cask/$($T.br).json" ("brew_cask_$($T.br).json")
    if ($cj) { $ck = $cj | ConvertFrom-Json; Classify $T.t $rel 'homebrew-cask' $ck.version $ck.url $ck.sha256 'cask' }
    else { Classify $T.t $rel 'homebrew' '' '' '' 'no formula or cask' }
  }

  # AUR -bin (release-asset sources only)
  $si = Fetch "https://aur.archlinux.org/cgit/aur.git/plain/.SRCINFO?h=$($T.aur)" ("aur_$($T.aur).SRCINFO")
  if (-not $si -or $si -notmatch 'pkgver') { Classify $T.t $rel 'aur-bin' '' '' '' "$($T.aur) not found" }
  else {
    $pv = ([regex]::Match($si, '(?m)^\s*pkgver\s*=\s*(\S+)')).Groups[1].Value
    foreach ($arch in '', '_x86_64', '_aarch64') {
      $srcs = @([regex]::Matches($si, "(?m)^\s*source$arch\s*=\s*(\S+)") | ForEach-Object { $_.Groups[1].Value })
      $shas = @([regex]::Matches($si, "(?m)^\s*sha256sums$arch\s*=\s*(\S+)") | ForEach-Object { $_.Groups[1].Value })
      for ($i = 0; $i -lt [Math]::Min($srcs.Count, $shas.Count); $i++) {
        $su = $srcs[$i]; if ($su -match '::') { $su = ($su -split '::', 2)[1] }
        if ($su -notmatch '/releases/download/') { continue }
        if ($shas[$i] -eq 'SKIP') { Classify $T.t $rel 'aur-bin' $pv $su '' "sha256 SKIP$arch"; continue }
        Classify $T.t $rel 'aur-bin' $pv $su $shas[$i] ($T.aur + $arch)
      }
    }
  }
}

$cols = 'tool','github_repo_id','tag','release_immutable','asset','github_digest','channel','channel_version','channel_url','channel_hash','result','note'
$sb = New-Object Text.StringBuilder
[void]$sb.Append(($cols -join "`t") + "`n")
foreach ($r in $rows) { [void]$sb.Append((($cols | ForEach-Object { ([string]$r.$_) -replace '[\t\r\n]', ' ' }) -join "`t") + "`n") }
[IO.File]::WriteAllText('D:\Projects\pakomichi\research\r-008\census.tsv', $sb.ToString(), $utf8)
[IO.File]::WriteAllText((Join-Path $raw 'releases-summary.txt'), (($summary -join "`n") + "`n"), $utf8)
$summary
"API calls: $($script:apiCalls); token used: $([bool]$script:tok)"
$rows | Group-Object channel, result | Sort-Object Name | ForEach-Object { "{0,4}  {1}" -f $_.Count, $_.Name }
