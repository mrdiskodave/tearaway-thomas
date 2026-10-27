# Tearaway Thomas converters

Scripts that turned the original Amiga data into the files the Java game
uses. They need Python 3 (3.8 or later) and two programs from
[Netpbm](https://netpbm.sourceforge.net/): `ilbmtoppm` and `pnmtopng`, on the
PATH.

## Graphics: pyblks.py

    python3 pyblks.py [converter ...]

Converters: `bobs` (all the sprites listed in `gfx.s`, from `odata/`), `tt`
(Thomas, from `orig/gfx/other/bits/tearaway.lbm`), `worlds` (block sheets
and masks), `font`, `topaz`, `horizons`, `star`. With none it runs `bobs`.
Output goes to `newdata/`.

The game's copies have been touched up by hand since, so expect these
differences from what's in the game's `src/com/nney/tt/resources`:

- some `def.txt` files (animation names, left and right swapped, extra frames)
- the block sheets: a few tiles removed, and the masks have no grey grid
  (the ghost world mask was also edited)
- `font.png` became `fonts/font2.png`, with red bars marking character widths
- single-frame sprites were moved from `name/000.png` to `name.png`
  (`tt_singleframes.py`)
- Thomas's `def.txt` was written by hand: his entry in `gfx.s` is commented
  out, so `tt` writes the frames only

Everything else matches the game exactly.

## Other scripts

- `pyunpack.py FILE...`: unpacks DHp2-packed files in place (runs a self test first)
- `mklevelinfo.py`: the level table from the original source, as JSON
- `splitsamples.py`: splits `samples.bin` into `samp4.bin` to `samp9.bin`
- `maprt.py`, `mudblks.py`: print block tables as JSON
- `find_legacy.py`: lists the alien types still held as legacy data in `tmp_maps/`
- `tt_singleframes.py`: run in an anims folder to flatten single-frame sprites (uses svn)
- `keydefs.py`, `colornumbers.py`: generated snippets for the old LWJGL code
