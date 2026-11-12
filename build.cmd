@echo off
setlocal
REM ADACLSizeAudit - build.cmd  (Open source - MIT License - https://adinternalshub.com/)
REM Builds ADACLSizeAudit.exe from source with the C# compiler that ships with the .NET Framework.
REM Works on Windows Server 2008 R2 SP1 and later with .NET Framework 4.0 or later installed (no Visual Studio needed).

set ROOT=%~dp0
set CSC=
for %%d in (Framework64 Framework) do (
  if exist "%WINDIR%\Microsoft.NET\%%d\v4.0.30319\csc.exe" if "%CSC%"=="" set CSC=%WINDIR%\Microsoft.NET\%%d\v4.0.30319\csc.exe
)
if "%CSC%"=="" (
  echo No .NET Framework 4.x C# compiler found under %WINDIR%\Microsoft.NET. Install .NET Framework 4.0 or later.
  exit /b 1
)
echo Using %CSC%
pushd "%ROOT%"
"%CSC%" /nologo /target:winexe /platform:anycpu /optimize+ /warn:3 /nowarn:1591 ^
  /out:ADACLSizeAudit.exe ^
  /win32icon:res\app.ico ^
  /resource:res\Dashboard.html,ADACLSizeAudit.Dashboard.html ^
  /r:System.dll /r:System.Core.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.DirectoryServices.Protocols.dll ^
  src\Model.cs src\SdParser.cs src\Ldap.cs src\Engine.cs src\Report.cs src\ToolMark.cs src\App.cs src\MainForm.cs Properties\AssemblyInfo.cs
set RC=%ERRORLEVEL%
if not "%RC%"=="0" (
  echo.
  echo Build FAILED with code %RC%.
  popd
  exit /b %RC%
)
copy /y ADACLSizeAudit.exe.config.template ADACLSizeAudit.exe.config >nul 2>nul
echo.
echo Build OK: %ROOT%ADACLSizeAudit.exe
echo Run without parameters for the front-end, or with /? for the command-line switches.
popd
endlocal
