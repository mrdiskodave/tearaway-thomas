#!/bin/sh
# Builds tearaway-thomas.jar. Needs only a JDK (21 or later).
set -e
cd "$(dirname "$0")"
rm -rf build/jar && mkdir -p build/jar
find src -name '*.java' \
  ! -name '*Test.java' ! -path 'src/sandbox/*' > build/sources.txt
javac --release 21 -nowarn -encoding UTF-8 -cp lib/lwjgl.jar -d build/jar @build/sources.txt
# the LWJGL front end (--lwjgl): its classes, and its Windows libraries, go in the jar too
(cd build/jar && jar xf ../../lib/lwjgl.jar && rm -f META-INF/MANIFEST.MF)
mkdir -p build/jar/natives/windows
cp nlib/windows/lwjgl.dll nlib/windows/lwjgl64.dll nlib/windows/OpenAL32.dll nlib/windows/OpenAL64.dll build/jar/natives/windows/
# resources (pngs, maps, music...) live alongside the code
(cd src && find . -type f ! -name '*.java' ! -path './sandbox/*' -exec sh -c 'mkdir -p "../build/jar/$(dirname "$1")" && cp "$1" "../build/jar/$1"' _ {} \;)
# (Enable-Native-Access: so Java 22+ lets LWJGL load its libraries without warnings)
printf 'Main-Class: com.nney.tt.j2d.J2dMain\nEnable-Native-Access: ALL-UNNAMED\n' > build/manifest.txt
jar cfm tearaway-thomas.jar build/manifest.txt -C build/jar .
echo "Built tearaway-thomas.jar - run it with: java -jar tearaway-thomas.jar"
