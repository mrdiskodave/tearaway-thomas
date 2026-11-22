# Tearaway Thomas

![Tearaway Thomas](tearaway.png)

Tearaway Thomas (Amiga, 1992, David Hanney and Nick Frampton), and the Java
remake of it.

| Folder | What's in it |
|--------|--------------|
| [`68k/`](68k) | The original game: its 68000 source (`s195`), graphics definitions, music, and the packed data files from the game disk |
| [`python/`](python) | The converters (2011): they unpack the original data and turn it into the artwork, maps and music the remake uses. See [`python/README.md`](python/README.md) |
| [`java/`](java) | The remake, begun in 2011 and taken up again in 2026. How to play, build and test it: [`java/README.md`](java/README.md) |

## History

The history goes back to the first converter, `pyunpack.py`, in February
2011. The remake's first commit followed on 1 March 2011, as an Eclipse
"Hello World" project of LWJGL graphics tests. Both were kept in Subversion
until 2012 (with a few converter changes in 2012 and 2017). Work resumed in
October 2026.

- Commits brought over from Subversion end with `SVN: r<number>`.
- A few converter changes survive only as their final contents; their
  commits say "original message not available".
- The branch `svn-2012-lost` holds 12 commits to the remake's music code
  (February to March 2012) that came from an older copy of the Subversion
  repository but never reached the code taken up in 2026.
