@echo off
rem Builds the project in the current folder (or the folder given as argument) and puts the
rem .exe in dist\ as <name>_v<version>.exe. Older .exe files in dist\ are removed.
rem Supports Rust, Go, .NET, Node.js, CMake (C/C++) and Python (PyInstaller).
rem An .ico file in the project becomes the icon of the .exe.
rem The rest of this file is PowerShell, run by the line below.
setlocal
set "BUILD_SELF=%~f0"
set "BUILD_DIR=%~1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex ((Get-Content -Raw -LiteralPath $env:BUILD_SELF) -split '(?m)^::PS\r?$', 2)[1]"
exit /b %errorlevel%
::PS
$ErrorActionPreference = 'Stop'

function Run {
  param([string]$exe)
  Write-Host "> $exe $args" -ForegroundColor DarkGray
  # Out-Host: show the tool's output instead of returning it to the caller.
  & $exe @args | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "$exe failed (exit code $LASTEXITCODE)." }
}

function Need($command, $hint) {
  if (-not (Get-Command $command -ErrorAction SilentlyContinue)) { throw "$command not found. $hint" }
}

# The `version = "x"` of the first of the given TOML tables that has one.
function Get-TomlVersion($file, [string[]]$tables) {
  if (-not (Test-Path -LiteralPath $file)) { return $null }
  $content = Get-Content -Raw -LiteralPath $file
  foreach ($table in $tables) {
    $header = [regex]::Match($content, "(?m)^\[$([regex]::Escape($table))\]\s*$")
    if (-not $header.Success) { continue }
    $body = ($content.Substring($header.Index + $header.Length) -split '(?m)^\[', 2)[0]
    $m = [regex]::Match($body, '(?m)^\s*version\s*=\s*["'']([^"'']*)["'']')
    if ($m.Success) { return $m.Groups[1].Value }
  }
  return $null
}

# Whether the current folder has a file matching one of the names/patterns.
function Test-File { [bool](Get-ChildItem -Path $args -File -ErrorAction SilentlyContinue) }

function Get-RegexVersion($file, $pattern) {
  $m = [regex]::Match((Get-Content -Raw -LiteralPath $file), $pattern)
  if ($m.Success) { $m.Groups[1].Value } else { $null }
}

# The project's icon: an .ico in the root or a usual assets folder; icon.ico, app.ico and <project>.ico win.
function Find-Icon($root) {
  $dirs = '.', 'assets', 'resources', 'res', 'build', 'icons', 'src' | Where-Object { Test-Path (Join-Path $root $_) }
  $icons = @($dirs | ForEach-Object { Get-ChildItem (Join-Path $root $_) -Filter *.ico -File })
  $preferred = 'icon', 'app', (Split-Path $root -Leaf)
  $best = $icons | Where-Object { $preferred -contains $_.BaseName } | Select-Object -First 1
  if (-not $best) { $best = $icons | Select-Object -First 1 }
  if ($best) { $best.FullName } else { $null }
}

# Writes an .ico into a finished .exe as its icon resource, for toolchains with no icon option.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

public static class ExeIcon {
  [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
  static extern IntPtr BeginUpdateResource(string file, bool deleteExisting);
  [DllImport("kernel32", SetLastError = true)]
  static extern bool UpdateResource(IntPtr handle, IntPtr type, IntPtr name, ushort language, byte[] data, int size);
  [DllImport("kernel32", SetLastError = true)]
  static extern bool EndUpdateResource(IntPtr handle, bool discard);

  const int RT_ICON = 3, RT_GROUP_ICON = 14;
  const ushort LANGUAGE = 1033;

  public static void Set(string exe, string ico) {
    byte[] file = File.ReadAllBytes(ico);
    int count = BitConverter.ToUInt16(file, 4);
    IntPtr handle = BeginUpdateResource(exe, false);
    if (handle == IntPtr.Zero) throw new Win32Exception();
    // The group lists the images: the .ico directory with resource ids in place of file offsets.
    byte[] group = new byte[6 + 14 * count];
    Array.Copy(file, 0, group, 0, 6);
    for (int i = 0; i < count; i++) {
      int entry = 6 + 16 * i;
      int size = BitConverter.ToInt32(file, entry + 8);
      byte[] image = new byte[size];
      Array.Copy(file, BitConverter.ToInt32(file, entry + 12), image, 0, size);
      if (!UpdateResource(handle, (IntPtr)RT_ICON, (IntPtr)(i + 1), LANGUAGE, image, size)) throw new Win32Exception();
      Array.Copy(file, entry, group, 6 + 14 * i, 12);
      BitConverter.GetBytes((ushort)(i + 1)).CopyTo(group, 6 + 14 * i + 12);
    }
    if (!UpdateResource(handle, (IntPtr)RT_GROUP_ICON, (IntPtr)1, LANGUAGE, group, group.Length)) throw new Win32Exception();
    if (!EndUpdateResource(handle, false)) throw new Win32Exception();
  }
}
'@

$stage = Join-Path $env:TEMP "build-stage-$PID"
try {
  if ($env:BUILD_DIR) { Set-Location -LiteralPath $env:BUILD_DIR }
  $root = (Get-Location).Path
  $dist = Join-Path $root 'dist'
  $version = $null
  $icon = Find-Icon $root
  # Whether the icon is written into the finished .exe; false where the build tool sets it itself.
  $stampIcon = $false

  # ---- Project type: sets $type, $version and $build (which returns the .exe files it made) ----

  if (Test-Path Cargo.toml) {
    $type = 'Rust'
    $stampIcon = $true
    $version = Get-TomlVersion 'Cargo.toml' @('package')
    $build = {
      if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH += ";$env:USERPROFILE\.cargo\bin" }
      Need cargo 'Install Rust from https://rustup.rs'
      Run cargo build --release
      Get-ChildItem target\release -Filter *.exe -File
    }
  } elseif (Test-Path go.mod) {
    $type = 'Go'
    $stampIcon = $true
    $build = {
      Need go 'Install Go from https://go.dev/dl'
      New-Item -ItemType Directory -Force $stage | Out-Null
      Run go build -o $stage ./...
      Get-ChildItem $stage -Filter *.exe -File
    }
  } elseif (Test-File *.sln *.slnx *.csproj *.fsproj *.vbproj) {
    $type = '.NET'
    $projects = @(Get-ChildItem -Recurse -File -Include *.csproj, *.fsproj, *.vbproj |
      Where-Object { $_.FullName -notmatch '\\(bin|obj|node_modules)\\' } |
      Where-Object { (Get-Content -Raw -LiteralPath $_.FullName) -match '<OutputType>\s*(Win)?Exe' })
    if ($projects.Count -eq 0) { throw 'No project with <OutputType>Exe</OutputType> found.' }
    $version = Get-RegexVersion $projects[0].FullName '<Version>\s*([^<\s]+)\s*</Version>'
    $build = {
      Need dotnet 'Install the .NET SDK from https://dotnet.microsoft.com/download'
      # Single file, so the .exe works on its own in dist (it still needs the .NET runtime installed).
      foreach ($project in $projects) {
        $hasIcon = (Get-Content -Raw -LiteralPath $project.FullName) -match '<ApplicationIcon>'
        $properties = @('-p:PublishSingleFile=true')
        if ($icon -and -not $hasIcon) { $properties += "-p:ApplicationIcon=$icon" }
        Run dotnet publish $project.FullName -c Release -r win-x64 --self-contained false -o $stage @properties
      }
      Get-ChildItem $stage -Filter *.exe -File
    }
  } elseif (Test-Path package.json) {
    $type = 'Node.js'
    $package = Get-Content -Raw package.json | ConvertFrom-Json
    $version = $package.version
    $script = 'dist', 'build' | Where-Object { $package.scripts.$_ } | Select-Object -First 1
    if (-not $script) { throw 'package.json has no "dist" or "build" script.' }
    # The .exe files already in dist, to tell them from the ones this build writes there.
    $stamp = { param($file) "$($file.LastWriteTimeUtc.Ticks) $($file.Length)" }
    $before = @{}
    if (Test-Path $dist) { Get-ChildItem $dist -Filter *.exe -File | ForEach-Object { $before[$_.Name] = & $stamp $_ } }
    $build = {
      # npm.cmd: PowerShell would pick npm.ps1, which loses the arguments.
      Need npm.cmd 'Install Node.js from https://nodejs.org'
      if (-not (Test-Path node_modules)) { Run npm.cmd install }
      Run npm.cmd run $script
      # The project's own packager (e.g. electron-builder) writes into dist, and sets the icon.
      if (Test-Path $dist) { Get-ChildItem $dist -Filter *.exe -File | Where-Object { $before[$_.Name] -ne (& $stamp $_) } }
    }
  } elseif (Test-Path CMakeLists.txt) {
    $type = 'CMake'
    $stampIcon = $true
    $version = Get-RegexVersion 'CMakeLists.txt' '(?is)\bproject\s*\([^)]*?\bVERSION\s+([\d.]+)'
    $build = {
      Need cmake 'Install CMake from https://cmake.org/download'
      Run cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
      Run cmake --build build --config Release
      Get-ChildItem build -Recurse -Filter *.exe -File | Where-Object { $_.FullName -notmatch '\\(CMakeFiles|Debug)\\' }
    }
  } elseif (Test-File pyproject.toml setup.py requirements.txt main.py app.py *.spec) {
    $type = 'Python'
    $version = Get-TomlVersion 'pyproject.toml' @('project', 'tool.poetry')
    $build = {
      $python = 'python', 'py' | Where-Object { Get-Command $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
      if (-not $python) { throw 'python not found. Install Python from https://www.python.org' }
      & $python -m PyInstaller --version *> $null
      if ($LASTEXITCODE -ne 0) { throw "PyInstaller not found. Install it with: $python -m pip install pyinstaller" }
      $work = Join-Path $root 'build\pyinstaller'
      $spec = Get-ChildItem -Filter *.spec -File | Select-Object -First 1
      if ($spec) {
        Run $python -m PyInstaller --noconfirm --distpath $stage --workpath $work $spec.FullName
      } else {
        $entry = 'main.py', 'app.py', '__main__.py', 'src\main.py' | Where-Object { Test-Path $_ } | Select-Object -First 1
        if (-not $entry) {
          $scripts = @(Get-ChildItem -Filter *.py -File | Where-Object { $_.Name -ne 'setup.py' })
          if ($scripts.Count -ne 1) { throw 'Cannot tell which script to build. Name the entry script main.py, or add a PyInstaller .spec file.' }
          $entry = $scripts[0].Name
        }
        $iconArgs = if ($icon) { '--icon', $icon } else { @() }
        Run $python -m PyInstaller --noconfirm --onefile --name (Split-Path $root -Leaf) --distpath $stage --workpath $work --specpath $work @iconArgs (Join-Path $root $entry)
      }
      Get-ChildItem $stage -Filter *.exe -File
    }
  } else {
    throw "No supported project found in $root (Cargo.toml, go.mod, .sln/.csproj, package.json, CMakeLists.txt, Python)."
  }

  # ---- Version: the project's own file, else a VERSION file ----

  if (-not $version -and (Test-Path VERSION)) { $version = (Get-Content -Raw VERSION).Trim() }
  if ("$version" -notmatch '^\d+\.\d+\.\d+') { throw 'No x.y.z version found. Add a VERSION file containing e.g. 0.1.0.' }

  Write-Host "=== Building $(Split-Path $root -Leaf) $version ($type) ===" -ForegroundColor Cyan
  $exes = @(& $build)
  if ($exes.Count -eq 0) { throw 'The build finished but produced no .exe.' }

  # ---- dist: remove the old .exe files, add the new ones ----

  New-Item -ItemType Directory -Force $dist | Out-Null
  Get-ChildItem $dist -Filter *.exe -File | Where-Object { $exes.FullName -notcontains $_.FullName } | Remove-Item -Force
  Write-Host ''
  foreach ($exe in $exes) {
    # A packager may have put the version in the name already.
    $name = if ($exe.BaseName.Contains($version)) { $exe.Name } else { "$($exe.BaseName)_v$version.exe" }
    $target = Join-Path $dist $name
    if ($exe.DirectoryName -ne $dist) { Copy-Item -LiteralPath $exe.FullName $target -Force }
    elseif ($exe.Name -ne $name) { Move-Item -LiteralPath $exe.FullName $target -Force }
    if ($stampIcon -and $icon) { [ExeIcon]::Set($target, $icon) }
    Write-Host "dist\$name" -ForegroundColor Green
  }
  if ($icon -and $type -ne 'Node.js') { Write-Host "Icon: $icon" }
} catch {
  Write-Host ''
  Write-Host "BUILD FAILED: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
} finally {
  if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
}
