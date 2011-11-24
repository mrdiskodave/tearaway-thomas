package com.nney.tt.mapper;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.OpenableTools;

public class ToyMaker {

	private static final int WIDTH = 20;
	private static final int WALL_COUNT = 4;
	private static final int HIDDEN_POS = 5;
	private static final int SOLID_POS = 1;
	private static final int PIPS_POS = 4;

	private static final int STYLE_SIZE = 2;
	private static final int STYLE_BASE = 6;
	private static final int STYLE_COUNT = 5;

	private static final int SHADOW_BASE = 16;
	private static final int SHADOW_COUNT = 7;

	private static final int FIRST = 0;
	private static final int SECOND = 1;
	private static final int BOTH = 2;

	private static final int COLOUR_STORE = 6;
	private static final int COLOUR_COUNT = 6;

	private BlockSource blocks;
	private int pos;

	private BlockSource[] colouredSources = new BlockSource[COLOUR_STORE];

	private Map<Integer, Integer> mapIn = new HashMap<Integer, Integer>();
	private Map<Integer, Integer> mapOut = new HashMap<Integer, Integer>();
	private BlockSource masks;

	static class S {
		int wall = -1;

		int col = 0;

		int style = -1;
		int which = -1;
		boolean pips = false;
		int shadow = 0;
		boolean hidden = false;

		@Override
		public String toString() {
			if (wall >= 0) {
				return String.format("wall%s col%s", wall, col);
			}
			assert style >= 0;
			return String.format("style%s which%s pips%s (col%s) shaddow%s hidden%s", style, which, pips, col, shadow,
					hidden);
		}

		int flattern() {
			return compose(col, pips ? 1 : 0, shadow, style, wall, which, hidden ? 1 : 0);
		}

		S col(int x) {
			col = x;
			return this;
		}

		S pips(boolean x) {
			pips = x;
			return this;
		}

		S shadow(int x) {
			shadow = x;
			return this;
		}

		public S style(int x, int y) {
			style = x;
			which = y;
			return this;
		}

		public S wall(int x) {
			wall = x;
			return this;
		}

		@Override
		protected S clone() throws CloneNotSupportedException {
			return (S) super.clone();
		}

		public S copy() {
			S a = new S();
			a.wall = wall;
			a.col = col;
			a.style = style;
			a.which = which;
			a.pips = pips;
			a.shadow = shadow;
			return a;

		}

		public boolean reduce() {
			if (wall >= 0) {
				if (wall == SOLID_POS || wall == HIDDEN_POS) return false;
				wall = SOLID_POS;
				return true;
			}
			assert style >= 0;
			if (which == 0 && !pips && shadow == 0) return false;
			which = 0;
			pips = false;
			col = 0;
			shadow = 0;
			return true;
		}

		public S hidden(boolean b) {
			hidden = b;
			return this;
		}
	}

	public static void main(String[] args) {
		new ToyMaker().testname();
	}

	public void testname() {
		TTResource.setResourcePath(new File("C:\\Users\\david\\Desktop\\z"));

		byte[] srcData = OpenableTools.mustLoad(TTResource.blocks("toyparts"));
		SimpleImage canvas = new SimpleImage(srcData);

		makeShaddowsTranslucent(canvas);

		{
			int x = 0;
			addColour(x++, canvas);
			addColour(x++, colouriseCanvas(canvas, 0xff006600, 0xff00aa00, 0xff00dd00));
			addColour(x++, colouriseCanvas(canvas, 0xff666600, 0xffaaaa00, 0xffdddd00));
			addColour(x++, colouriseCanvas(canvas, 0xff006666, 0xff00aaaa, 0xff00dddd));
			addColour(x++, colouriseCanvas(canvas, 0xffaaaaaa, 0xffdddddd, 0xffffffff));
			addColour(x++, colouriseCanvas(canvas, 0xff444444, 0xff888888, 0xffdddddd));
			// addColour(x++, colouriseCanvas(canvas, 0xffffff00, 0xffaaaa00,
			// 0xffdddd00));
			assert x == COLOUR_STORE;
		}

		//
		//
		// 0-5 wall with this palette:
		// ff000000
		// ff660000
		// ffaa1100
		// ffdd3300
		//
		// 6-13 backgrounds
		//
		// 14-19 shadows
		//

		gen();
		int rowsNeeded = Math2.roundUpDiv(pos, WIDTH);
		int w = Const.BLOCK_SIZE * WIDTH;
		int h = Const.BLOCK_SIZE * rowsNeeded;
		SimpleImage blocksImage = SimpleImage.createEmpty(w, h);
		SimpleImage masksImage = SimpleImage.createEmpty(w, h);
		masksImage.fill(0xffffffff);

		blocks = new BlockSource(blocksImage, Const.BLOCK_SIZE);
		masks = new BlockSource(masksImage, Const.BLOCK_SIZE);
		pos = 0;
		gen();

		saveForExamination(blocksImage, "blocks");
		saveForExamination(masksImage, "masks");
	}

	public void gen() {
		// ***********************************************
		// TODO 000 colouring and ordering next!! :)
		// ***********************************************

		//
		// basic stuff for drawing with
		//
		for (int col = 0; col < COLOUR_COUNT; col++) {
			copy(s().col(col).wall(SOLID_POS)); // solid
		}
		nextRow();
		for (int style = 0; style < STYLE_COUNT; style++) {
			// empty (in various styles)
			copy(s().style(style, FIRST));
		}
		nextRow();
		for (int style = 0; style < STYLE_COUNT; style++) {
			// hidden (in various styles)
			copy(s().style(style, FIRST).hidden(true));
		}
		nextRow();

		//
		// extended stuff for generating with
		//

		// coloured stuff
		for (int col = 0; col < COLOUR_COUNT; col++) {
			// rest of wall
			for (int x = 0; x < WALL_COUNT; x++) {
				if (x != SOLID_POS) {
					copy(s().col(col).wall(x));
				}
			}
			// coloured pips
			for (int style = 0; style < STYLE_COUNT; style++) {
				for (int shadow = 0; shadow < SHADOW_COUNT; shadow++) {
					copy(s().col(col).shadow(shadow).pips(true).style(style, BOTH));
				}
			}
		}

		// plain stuff
		for (int style = 0; style < STYLE_COUNT; style++) {
			copy(s().style(style, SECOND).hidden(true));
			for (int shadow = 0; shadow < SHADOW_COUNT; shadow++) {
				boolean doneFirst = shadow == 0;
				int which = doneFirst ? SECOND : BOTH;
				copy(s().shadow(shadow).style(style, which));
			}
		}
	}

	private void nextRow() {
		pos = ((pos / WIDTH) + 1) * WIDTH;
	}

	private void addColour(int i, SimpleImage si) {
		colouredSources[i] = new BlockSource(si, Const.BLOCK_SIZE);
	}

	public SimpleImage colouriseCanvas(SimpleImage canvas, int n1, int n2, int n3) {
		SimpleImage si;
		int red1 = 0xff660000;
		int red2 = 0xffaa1100;
		int red3 = 0xffdd3300;
		si = canvas.copy();
		PaletteChanger pc = new PaletteChanger();
		pc.add(red1, n1);
		pc.add(red2, n2);
		pc.add(red3, n3);
		si.changePixels(pc);
		return si;
	}

	public void saveForExamination(SimpleImage destImage, String name) {
		//
		// save to disk
		//
		try {
			String fn = String.format("\\\\10.0.0.3\\x\\x\\tt\\%s.pnm", name);
			System.out.println("Saving " + fn);
			OutputStream o = new BufferedOutputStream(new FileOutputStream(fn));
			destImage.writeP6(o);
			o.close();
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	static public S s() {
		return new S();
	}

	public void makeShaddowsTranslucent(SimpleImage canvas) {
		{
			BlockSource bs5 = new BlockSource(canvas, Const.BLOCK_SIZE);
			for (int shadow = 0; shadow < 6; shadow++) {
				int shadowIdx = SHADOW_BASE + shadow;
				SimpleImage b = bs5.getBlock(shadowIdx);
				b.changePixels(new ChangePixel() {
					@Override
					public int change(int c) {
						int alpha = c >>> 3 * 8;
						if (alpha == 0) {
							return 0;
						}
						return 0x80000000;
					}
				});
			}
		}
	}

	public void copy(S s) {
		if (s.which == BOTH) {
			S s2 = s.copy();
			s.which = FIRST;
			s2.which = SECOND;
			copy(s);
			copy(s2);
		}
		else {
			if (blocks != null) {
				boolean solid = false;
				recordMapping(s);
				SimpleImage d = blocks.getBlock(pos);
				if (s.wall >= 0) {
					d.mergeWith(getSrc(s.col, s.wall));
					solid = true;
				}
				else {
					assert s.style >= 0;
					int sp = STYLE_BASE + s.style * STYLE_SIZE;
					d.mergeWith(getSrc(0, sp + s.which));
					if (s.pips) {
						d.mergeWith(getSrc(s.col, PIPS_POS));
					}
					if (s.shadow != 0) {
						d.mergeWith(getSrc(0, SHADOW_BASE + s.shadow - 1));
					}
					if (s.hidden) {
						solid = true;
						d.mergeWith(getSrc(0, HIDDEN_POS));
					}
				}
				if (solid) {
					masks.getBlock(pos).fill(0xff000000);
				}
			}

			pos++;
		}
	}

	static private int compose(int... d) {
		int x = 0;
		for (int i : d) {
			assert i >= -1 && i <= 14;
			x <<= 4;
			x |= i & 15;
		}
		return x;
	}

	private SimpleImage getSrc(int col, int i) {
		return colouredSources[col].getBlock(i);
	}

	private void recordMapping(S d) {
		System.out.println(String.format("%03d %s", pos, d));
		int f = d.flattern();

		S d2 = d.copy();
		if (d2.reduce()) {
			int backTo = d2.flattern();
			Integer b = mapIn.get(backTo);
			assert b!=null;
			System.out.println(String.format("maps back to %s %03d", d2, b));
		}

		assert !mapIn.containsKey(f);
		mapIn.put(f, pos);

		assert !mapOut.containsKey(pos);
		mapIn.put(pos, f);
	}
}
