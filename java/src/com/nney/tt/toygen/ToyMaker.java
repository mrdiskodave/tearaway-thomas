package com.nney.tt.toygen;

import java.util.HashMap;
import java.util.Map;

import com.nney.tt.Const;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.map.BlockAliasTable;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Math2;
import com.nney.utils.OpenableTools;

public class ToyMaker {
	private static final int SPACE_BASE = 6;
	private static final int SPECIAL_POS = 5;
	private static final int SOLID_POS = 1;
	private static final int PIPS_POS = 4;
	private static final int SPACE_SIZE = 2;
	private static final int SHADOW_BASE = 16;

	private static final int COLOUR_MAX = 20;

	private int colourCount;

	private BlockSource blocks;
	private BlockSource masks;
	private int pos;

	private BlockSource[] colouredSources = new BlockSource[COLOUR_MAX];

	private BlockInformation blockInformation = new BlockInformation();

	private BlockAliasTable hiding = new BlockAliasTable();

	private BlockAliasTable compression = new BlockAliasTable();

	private Map<Integer, Integer> where;

	// public static void main(String[] args) {
	// new ToyMaker().generate();
	// }

	// TTResource.setResourcePath(new File("C:\\Users\\david\\Desktop\\z"));

	static public class Result {
		public final SimpleImage blocks;
		public final SimpleImage masks;
		public final BlockInformation blockInformation;
		public final Map<Integer, Integer> where;
		public final BlockAliasTable hiding;
		public final BlockAliasTable compression;

		public Result(SimpleImage blocks, SimpleImage masks, BlockInformation blockInformation,
				Map<Integer, Integer> where, BlockAliasTable hiding, BlockAliasTable compression) {
			this.blocks = blocks;
			this.masks = masks;
			this.blockInformation = blockInformation;
			this.where = where;
			this.hiding = hiding;
			this.compression = compression;
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

		generateBlocks();
		int rowsNeeded = Math2.roundUpDiv(pos, S.WIDTH);
		int w = Const.BLOCK_SIZE * S.WIDTH;
		int h = Const.BLOCK_SIZE * rowsNeeded;

		SimpleImage blocksImage = SimpleImage.createEmpty(w, h);
		SimpleImage masksImage = SimpleImage.createEmpty(w, h);
		masksImage.fill(0xffffffff);
		blocks = new BlockSource(blocksImage, Const.BLOCK_SIZE);
		masks = new BlockSource(masksImage, Const.BLOCK_SIZE);
		generateBlocks();
		return new Result(blocksImage, masksImage, blockInformation, where, hiding, compression);

		// saveForExamination(blocksImage, "blocks");
		// saveForExamination(masksImage, "masks");
	}

	private void generateBlocks() {
		where = new HashMap<>();

		//
		// basic stuff for drawing with
		//
		pos = S.rSpaces.start;
		for (int style = 0; style < S.SPACE_COUNT; style++) {
			// empty (in various styles)
			copy(s().space(style));
		}
		pos = S.rWalls.start;
		for (int col = 0; col < colourCount; col++) {
			copy(s().col(col).wall(SOLID_POS)); // solid
		}
		pos = S.rSpecial.start;
		// hidden (in various styles)
		copy(s().special(S.SPECIAL_MAGIC));
		pos = S.rSpecial.end;

		//
		// extended stuff for generating with
		//

		// coloured stuff
		for (int col = 0; col < colourCount; col++) {
			// rest of wall
			for (int x = 0; x < S.WALL_COUNT; x++) {
				copy(s().col(col).wall(x));
			}
			// coloured pips
			for (int style = 0; style < S.SPACE_COUNT; style++) {
				for (int shadow = 0; shadow < S.SHADOW_COUNT; shadow++) {
					copyBoth(s().col(col).shadow(shadow).pips(true).space(style));
				}
			}

		}
		// plain stuff
		for (int style = 0; style < S.SPACE_COUNT; style++) {
			for (int shadow = 0; shadow < S.SHADOW_COUNT; shadow++) {
				copyBoth(s().shadow(shadow).space(style));
			}
			copyBoth(s().space(style).special(S.SPECIAL_MAGIC));
		}
	}

	private void addColour(int i, SimpleImage si) {
		colouredSources[i] = new BlockSource(si, Const.BLOCK_SIZE);
	}

	private SimpleImage colouriseCanvas(SimpleImage canvas, int n1, int n2, int n3) {
		// the original palette:
		int red1 = 0xff660000;
		int red2 = 0xffaa1100;
		int red3 = 0xffdd3300;

		PaletteChanger pc = new PaletteChanger();
		pc.add(red1, n1);
		pc.add(red2, n2);
		pc.add(red3, n3);
		SimpleImage si = canvas.copy();
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

	static private S s() {
		return new S();
	}

	private void makeShaddowsTranslucent(SimpleImage canvas) {
		{
			BlockSource bs5 = new BlockSource(canvas, Const.BLOCK_SIZE);
			for (int shadow = 0; shadow < 6; shadow++) {
				int shadowIdx = SHADOW_BASE + shadow;
				SimpleImage b = bs5.getBlock(shadowIdx);
				b.changePixels(c -> (c >>> 3 * 8) == 0 ? 0 : 0x80000000);
			}
		}
	}

	private void copyBoth(S s) {
		copy(s);
		copy(s.copy().which(true));
	}

	private void copy(S s) {
		if (recordMapping(s)) {
			if (blocks != null) {

				if (pos >= S.rSpecial.end) {
					// compression!
					System.out.println(String.format("From %s (%s)", s, pos));
					S c = s.copy().shadow(0).pips(false).which(false);
					if (c.isWall()) {
						c.wall(SOLID_POS);
					}
					if (c.isSpace()) {
						c.col(0);
					}
					if (c.isSpecial()) {
						c.wall(S.NONE);
						c.space(S.NONE);
					}
					System.out.println(String.format("Made %s", c));
					compression.registerCompression(pos, where.get(c.flattern()));
				}

				if (s.special() == S.SPECIAL_MAGIC) {
					// System.out.println("MAGIC:" + pos);
					blockInformation.put(pos, "magic");
					S s2 = s.copy().special(S.NONE);
					Integer nonMagic = where.get(s2.flattern());
					if (nonMagic != null) {
						// System.out.println(String.format("HIDE: %s -> %s",
						// pos, nonMagic));
						hiding.registerCompression(pos, nonMagic);
					}
				}

				boolean solid = false;
				SimpleImage d = blocks.getBlock(pos);
				if (s.wall() >= 0) {
					d.mergeWith(getSrc(s.col(), s.wall()));
					solid = true;
				}
				else {
					if (s.space() >= 0) {
						int z = s.space();
						if (z != 0) {
							z--;
							z = SPACE_BASE + z * SPACE_SIZE;
							if (s.isWhich()) z++;
							d.mergeWith(getSrc(0, z));
						}
					}
					if (s.shadow() != 0) {
						d.mergeWith(getSrc(0, SHADOW_BASE + s.shadow() - 1));
					}
					if (s.isPips()) {
						d.mergeWith(getSrc(s.col(), PIPS_POS));
					}
					if (s.isSpecial()) {
						int z = s.special();
						d.mergeWith(getSrc(0, SPECIAL_POS + z));
						solid |= z == S.SPECIAL_MAGIC;
					}
				}
				if (solid) {
					masks.getBlock(pos).fill(0xff000000);
				}
			}
			pos++;
		}
	}

	// public WorldInformation getWorldInformation() {
	// return new WorldInformation(new BlockAliasTable(), new BlockAliasTable(),
	// blockInformation, null);
	// }

	private SimpleImage getSrc(int col, int i) {
		return colouredSources[col].getBlock(i);
	}

	private boolean recordMapping(S s) {
		int f = s.flattern();
		// System.out.println(String.format("%03d %08x %s", pos, f, s));
		if (where.containsKey(f)) {
			// System.out.println("SEEN ALREADY!");
			return false;
		}
		where.put(f, pos);
		return true;
	}
}
