@echo off
rem Build the capnagent-wasm artifact for bundler consumers.
rem
rem Windows-native counterpart to scripts/build-wasm.sh. Invokes
rem `wasm-pack build` with the same arguments the npm `build:wasm`
rem script uses, but works from cmd.exe / PowerShell without a bash
rem shim.
rem
rem Output: crates\capnagent-wasm\pkg\ - covered by .gitignore.

setlocal

rem Resolve the repo root from this script's location so the command
rem works from any CWD.
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%.." >NUL
set "REPO_ROOT=%CD%"
popd >NUL

cd /d "%REPO_ROOT%"

where wasm-pack >NUL 2>&1
if errorlevel 1 (
  echo error: wasm-pack not found on PATH. 1>&2
  echo        install with: cargo install wasm-pack 1>&2
  exit /b 127
)

wasm-pack build crates\capnagent-wasm --target bundler --out-dir pkg %*
exit /b %ERRORLEVEL%
