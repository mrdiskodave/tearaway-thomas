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

It starts like the original: the title sequence runs over a demo of level 1,
followed by demos of each world (the original Amiga demo recordings). Press
jump to play. Game over, or finishing all 50 levels, leads to the high score
table, then back to the titles. High scores are kept in
`~/.tearaway-thomas/hiscores.txt` (in your user folder on Windows).

Options:

    --level N       skip the titles and start a game on level N (0 = first of 50)
    --dev           developer keys: Esc opens the map editor, D runs out the clock,
                    N skips to the next level
    --demo NAME     (with --level) play one of the demo recordings: intro, wood,
                    toy, ghost, ice, future
    --mapper        start in the map editor
    --mute          no sound
    --scale N       initial window size (default 2x)

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
- `com.nney.tt.lwjgl`: the original LWJGL 2 / OpenGL platform layer. It still
  compiles against `lib/*.jar` but is no longer needed or built into the jar.
- `com.nney.tt.resources`: all the converted artwork, maps and music.

## Automated testing

`--headless` runs without a window, as fast as possible:

    java -jar tearaway-thomas.jar --headless --level 3 --frames 1000 \
         --capture frames/ --every 25 --input "100:F,104:-,120:R,300:RF,306:R" --wav out.wav

`--input` is a scripted joystick (`frame:buttons`, with buttons from U D L R F,
lower case letters for keys, and `-` for none).

Unit tests: `build/test.sh` (needs `lib/*.jar` and JUnit 4 in `build/extlib`).
