@echo off
rem Builds tearaway-thomas.jar. Needs only a JDK (21 or later) on the PATH.
setlocal
cd /d "%~dp0"
if exist build\jar rmdir /s /q build\jar
mkdir build\jar

rem everything except tests and sandbox demos
dir /s /b src\*.java | findstr /v /i /r /c:"Test\.java$" /c:"\\sandbox\\" > build\sources.txt
rem javac @files need forward slashes or quoted paths
powershell -NoProfile -Command "(Get-Content build\sources.txt) | ForEach-Object { '\"' + ($_ -replace '\\','/') + '\"' } | Set-Content build\sources.txt"

javac --release 21 -nowarn -encoding UTF-8 -cp lib\lwjgl.jar -d build\jar @build\sources.txt
if errorlevel 1 goto :fail

rem the LWJGL front end (--lwjgl): its classes, and its Windows libraries, go in the jar too
pushd build\jar
jar xf ..\..\lib\lwjgl.jar
if errorlevel 1 (popd & goto :fail)
del META-INF\MANIFEST.MF
popd
mkdir build\jar\natives\windows
for %%f in (lwjgl.dll lwjgl64.dll OpenAL32.dll OpenAL64.dll) do copy /y nlib\windows\%%f build\jar\natives\windows\ >nul

rem resources (pngs, maps, music...) live alongside the code
robocopy src build\jar /s /xf *.java /xd sandbox /njh /njs /nfl /ndl >nul

rem (Enable-Native-Access: so Java 22+ lets LWJGL load its libraries without warnings)
echo Main-Class: com.nney.tt.j2d.J2dMain> build\manifest.txt
echo Enable-Native-Access: ALL-UNNAMED>> build\manifest.txt
jar cfm tearaway-thomas.jar build\manifest.txt -C build\jar .
if errorlevel 1 goto :fail

echo Built tearaway-thomas.jar - run it with: java -jar tearaway-thomas.jar
exit /b 0

:fail
echo Build failed.
exit /b 1
