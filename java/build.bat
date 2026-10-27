@echo off
rem Builds tearaway-thomas.jar. Needs only a JDK (11 or later; the jar itself runs on Java 8+) on the PATH.
setlocal
cd /d "%~dp0"
if exist build\jar rmdir /s /q build\jar
mkdir build\jar

rem everything except tests, sandbox demos and the old LWJGL backend
dir /s /b src\*.java | findstr /v /i /r /c:"Test\.java$" /c:"\\sandbox\\" /c:"\\com\\nney\\tt\\lwjgl\\" > build\sources.txt
rem javac @files need forward slashes or quoted paths
powershell -NoProfile -Command "(Get-Content build\sources.txt) | ForEach-Object { '\"' + ($_ -replace '\\','/') + '\"' } | Set-Content build\sources.txt"

javac --release 8 -nowarn -encoding UTF-8 -d build\jar @build\sources.txt
if errorlevel 1 goto :fail

rem resources (pngs, maps, music...) live alongside the code
robocopy src build\jar /s /xf *.java /xd sandbox /njh /njs /nfl /ndl >nul

echo Main-Class: com.nney.tt.j2d.J2dMain> build\manifest.txt
jar cfm tearaway-thomas.jar build\manifest.txt -C build\jar .
if errorlevel 1 goto :fail

echo Built tearaway-thomas.jar - run it with: java -jar tearaway-thomas.jar
exit /b 0

:fail
echo Build failed.
exit /b 1
