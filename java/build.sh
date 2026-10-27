#!/bin/sh
# Builds tearaway-thomas.jar. Needs only a JDK (21 or later).
set -e
cd "$(dirname "$0")"
rm -rf build/jar && mkdir -p build/jar
find src -name '*.java' \
  ! -name '*Test.java' ! -path 'src/sandbox/*' ! -path 'src/com/nney/tt/lwjgl/*' > build/sources.txt
javac --release 21 -nowarn -encoding UTF-8 -d build/jar @build/sources.txt
# resources (pngs, maps, music...) live alongside the code
(cd src && find . -type f ! -name '*.java' ! -path './sandbox/*' -exec sh -c 'mkdir -p "../build/jar/$(dirname "$1")" && cp "$1" "../build/jar/$1"' _ {} \;)
printf 'Main-Class: com.nney.tt.j2d.J2dMain\n' > build/manifest.txt
jar cfm tearaway-thomas.jar build/manifest.txt -C build/jar .
echo "Built tearaway-thomas.jar - run it with: java -jar tearaway-thomas.jar"
