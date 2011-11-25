package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map;

import com.nney.tt.Const;
import com.nney.tt.LadderInformation;
import com.nney.tt.WorldInformation;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;
import com.nney.tt.map.BlockAliasTable;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.Mapper.BlockAccess;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.OpenableTools;

public class ToyMaker {
	public static final int WIDTH = 20;

	private static final int NPOS_BLOCKS = 0;
	private static final int NPOS_STYLE = WIDTH;
	private static final int NPOS_HIDDEN = 2 * WIDTH;

	private static final int WALL_COUNT = 4;
	private static final int MAGIC_POS = 5;
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

	private static final int COLOUR_MAX = 20;

	private int colourCount;

	private BlockSource blocks;
	private BlockSource masks;
	private int pos;

	private BlockSource[] colouredSources = new BlockSource[COLOUR_MAX];

	private Map<Integer, Integer> flatternedToPos = new HashMap<Integer, Integer>();

	private BlockAccess blockAccess2;
	
	private BlockInformation blockInformation = new BlockInformation();

	static class S {
		int wall = -1;

		int col = 0;

		int style = -1;
		int which = -1;
		boolean pips = false;
		int shadow = 0;
		boolean magic = false;

		@Override
		public String toString() {
			if (wall >= 0) {
				return String.format("wall%s col%s", wall, col);
			}
			// assert style >= 0;
			return String.format("style%s which%s pips%s (col%s) shaddow%s magic%s", style, which, pips, col, shadow,
					magic);
		}

		int flattern() {
			return compose(col, pips ? 1 : 0, shadow, style, wall, which, magic ? 1 : 0);
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

		public S magic(boolean b) {
			magic = b;
			return this;
		}

		public S copy() {
			S a = new S();
			a.wall = wall;
			a.col = col;
			a.style = style;
			a.which = which;
			a.pips = pips;
			a.shadow = shadow;
			a.magic = magic;
			return a;
		}
	}

	public static void main(String[] args) {
		new ToyMaker().generate();
	}

	// TTResource.setResourcePath(new File("C:\\Users\\david\\Desktop\\z"));

	static class Result {
		public final SimpleImage blocks;
		public final SimpleImage masks;

		public Result(SimpleImage blocks, SimpleImage masks) {
			this.blocks = blocks;
			this.masks = masks;
		}
	}

	public Result generate() {
		byte[] srcData = OpenableTools.mustLoad(TTResource.blocks("toyparts"));
		SimpleImage canvas = new SimpleImage(srcData);
		makeShaddowsTranslucent(canvas);

		int c = 0;
		addColour(c++, canvas);
		addColour(c++, colouriseCanvas(canvas, 0xff006600, 0xff00aa00, 0xff00dd00));
		addColour(c++, colouriseCanvas(canvas, 0xff666600, 0xffaaaa00, 0xffdddd00));
		addColour(c++, colouriseCanvas(canvas, 0xff006666, 0xff00aaaa, 0xff00dddd));
		addColour(c++, colouriseCanvas(canvas, 0xffaaaaaa, 0xffdddddd, 0xffffffff));
		addColour(c++, colouriseCanvas(canvas, 0xff444444, 0xff888888, 0xffdddddd));
		colourCount = c;

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
		return new Result(blocksImage, masksImage);

		// saveForExamination(blocksImage, "blocks");
		// saveForExamination(masksImage, "masks");
	}

	public void gen() {
		//
		// basic stuff for drawing with
		//
		for (int col = 0; col < colourCount; col++) {
			copy(s().col(col).wall(SOLID_POS)); // solid
		}
		nextRow();
		for (int style = 0; style < STYLE_COUNT; style++) {
			// empty (in various styles)
			copy(s().style(style, FIRST));
		}
		nextRow();
		// hidden (in various styles)
		copy(s().magic(true));
		nextRow();

		//
		// extended stuff for generating with
		//

		// coloured stuff
		for (int col = 0; col < colourCount; col++) {
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
			copy(s().style(style, BOTH).magic(true));
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
		//
		//
		// original wall has this palette
		// ff000000
		// ff660000
		// ffaa1100
		// ffdd3300
		//

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

	// private void saveForExamination(SimpleImage destImage, String name) {
	// //
	// // save to disk
	// //
	// try {
	// String fn = String.format("\\\\10.0.0.3\\x\\x\\tt\\%s.pnm", name);
	// System.out.println("Saving " + fn);
	// OutputStream o = new BufferedOutputStream(new FileOutputStream(fn));
	// destImage.writeP6(o);
	// o.close();
	// }
	// catch (IOException e) {
	// throw new RuntimeException(e);
	// }
	// }

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
					if (s.style >= 0) {
						int sp = STYLE_BASE + s.style * STYLE_SIZE;
						d.mergeWith(getSrc(0, sp + s.which));
					}
					if (s.pips) {
						d.mergeWith(getSrc(s.col, PIPS_POS));
					}
					if (s.shadow != 0) {
						d.mergeWith(getSrc(0, SHADOW_BASE + s.shadow - 1));
					}
					if (s.magic) {
						blockInformation.put(pos, "magic");
						d.mergeWith(getSrc(0, MAGIC_POS));
					}
				}
				if (solid) {
					masks.getBlock(pos).fill(0xff000000);
				}
			}

			pos++;
		}
	}
	
	public WorldInformation getWorldInformation() {
		return new WorldInformation(new BlockAliasTable(), new BlockAliasTable(), blockInformation, null);
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

	private void recordMapping(S s) {
		System.out.println(String.format("%03d %s", pos, s));
		flatternedToPos.put(s.flattern(), pos);
	}

	public int get(S s) {
		Integer answer = flatternedToPos.get(s.flattern());
		assert answer != null;
		return answer;
	}

	private int a(int b, int x) {
		if (b >= x && b < x + WIDTH) {
			return b - x;
		}
		return -1;
	}

	private int isWall(int b) {
		return a(b, NPOS_BLOCKS);
	}

	private int isSpace(int b) {
		return a(b, NPOS_STYLE);
	}

	private boolean testWall(Coord coord, int i, int j) {
		int b = blockAccess2.get(coord.copyAndAdd(i, j));
		return isWall(b) >= 0;
	}

	public void generateToyland(BlockAccess blockAccess) {
		this.blockAccess2 = blockAccess;

		System.out.println("Generating Intricacies Of Toyland");
		for (int y = 0; y < blockAccess.width(); y++) {
			for (int x = 0; x < blockAccess.height(); x++) {
				Coord coord = new Coord(x, y);

				int checkers = (x ^ y) & 1;

				boolean wallEast = testWall(coord, 1, 0);
				boolean wallWest = testWall(coord, -1, 0);
				boolean wallNorthWest = testWall(coord, -1, -1);
				boolean wallNorth = testWall(coord, 0, -1);
				boolean wallSouth = testWall(coord, 0, 1);

				int walls[] = { 3, 2, 0, 1 };
				int shadows[] = { 0, 5, 3, 2, 4, -1, 6, 1 };

				int b = blockAccess.get(coord);
				int wallColour = isWall(b);
				int spaceNumber = isSpace(b);
				int n = -1;

				if (wallColour >= 0) {
					int v = 0;
					if (wallWest) v |= 1;
					if (wallEast) v |= 2;
					v = walls[v];
					n = get(s().wall(v).col(wallColour));
				}
				else if (spaceNumber >= 0) {
					int v = 0;
					if (wallNorth) v |= 1;
					if (wallNorthWest) v |= 2;
					if (wallWest) v |= 4;
					v = shadows[v];
					if (v>=0) {
						n = get(s().style(spaceNumber, checkers).shadow(v).pips(wallSouth));
					}
				}
				else if (b == NPOS_HIDDEN) {
					int b2 = blockAccess.get(coord.copyAndAdd(0, 1));
					b2 = isSpace(b2);
					if (b2 >= 0) {
						n = get(s().style(b2, checkers).magic(true));
					}
				}
				else {
					System.out.println(String.format("Something else: %s at %s", b, coord));
				}

				if (n >= 0) {
					blockAccess.set(coord, n);
				}
			}
		}
	}
}
