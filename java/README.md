# Tearaway Thomas (Java)

A Java remake of Tearaway Thomas (Amiga, 1992, David Hanney and Nick Frampton).

## Play

    java -jar tearaway-thomas.jar

Needs Java 21 or later. No other libraries are needed.

| Action | Keys |
|---|---|
| Move | Cursor keys, or the original Q / A / [ / ] |
| Jump (fire) | Space, Ctrl or Z |
| Pause | P |
| Full screen | Alt+Enter or F11 |

It runs like the original: the title pages over a demo of level 1, then one
world's demo (the original Amiga recordings), then the titles again and the
next world, until you press jump. Each level opens with the circle, then says
what the level is and waits for jump. After the last level the game goes round
again from the first. After game over, a new high score's name is entered over
the next demo. High scores are kept in `~/.tearaway-thomas/hiscores.txt` (in
your user folder on Windows).

Options (`-h` or `--help` lists them all):

    --level N       skip the titles and start a game on level N (0 = first of 50)
    --dev           developer keys: Esc opens the map editor, D runs out the clock,
                    N finishes the level
    --demo NAME     (with --level) play one of the demo recordings: intro, wood,
                    toy, ghost, ice, future
    --at X,Y        (with --level) start the player at this map position
    --mapper        start in the map editor
    --mute          no sound
    --sound-device TEXT
                    play sound on the device with TEXT in its name (e.g. realtek)
                    instead of Windows' default
    --beep          sound test: a beep, and the sound devices Java can see
    --scale N       initial window size (default 2x)
    --lwjgl         use the original LWJGL front end (OpenGL and OpenAL, Windows
                    only) instead of Java2D; it takes --level, --dev and --mapper

When run from a command prompt it prints the frame rate every 4 seconds.

## Build

    build.bat        (Windows)
    ./build.sh       (macOS / Linux)

Both need only a JDK (21 or later) and produce `tearaway-thomas.jar`.

## Code layout

- `com.nney.tt`: the game (World, Player, aliens, maps, sprites, music player)
- `com.nney.tt.flow`: everything outside a level. Title sequence and demos,
  game over, the ending, high scores. Written as straight-line code;
  see `GameFlow`.
- `com.nney.coroutines`: coroutines on Java 21 virtual threads. The title
  sequence is one, stepped once a frame by the demo it runs over.
- `com.nney.tt.j2d`: the platform layer. Java2D graphics, javax.sound audio,
  AWT keyboard and mouse. This is the one in use.
- `com.nney.tt.lwjgl`: the original LWJGL 2 platform layer (OpenGL, OpenAL),
  started with `--lwjgl`. The build puts `lib/lwjgl.jar` and the Windows
  libraries from `nlib/windows` into the jar; they're unpacked to a temp
  folder when it starts.
- `com.nney.tt.resources`: all the converted artwork, maps and music.
- `com.nney.tt.tools.MapTool`: converts objects still held as raw Amiga data
  ("legacy" objects) in the level files into proper ones, once their type has
  a Java class. Edits just those objects. (Every level is now converted.)

## Automated testing

`--headless` runs without a window, as fast as possible:

    java -jar tearaway-thomas.jar --headless --level 3 --frames 1000 \
         --capture frames/ --every 25 --input "100:F,104:-,120:R,300:RF,306:R" --wav out.wav

`--input` is a scripted joystick (`frame:buttons`, with buttons from U D L R F,
lower case letters for keys, and `-` for none).

Unit tests: `build/test.sh` (needs `lib/*.jar` and JUnit 4 in `build/extlib`).
