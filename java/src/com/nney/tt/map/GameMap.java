package com.nney.tt.map;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public final class GameMap {
	// use of these private constants are the only place
	// where map size is still hard-wired 
	private final static int OMAP_WIDTH = 256;
	private final static int OMAP_HEIGHT = 128;
	// this opens up the possibility of megamaps!!!

	private final Box boundsInPixels;

	private final short[][] map;
	private final int w;
	private final int h;
	
	public int width() {
		return w;
	}
	
	public int height() {
		return h;
	}

	public GameMap() {
		this(OMAP_WIDTH, OMAP_HEIGHT);
	}
	
	private GameMap(int w, int h) {
		this.w = w;
		this.h = h;
		map = new short[h][w];
		boundsInPixels = Box.fromTopLeftAndSize(0, 0, w
				* Const.BLOCK_SIZE, h * Const.BLOCK_SIZE);
	}
	
	public Box boundsInPixels() {
		return boundsInPixels;
	}
	
//	public static GameMap loadLegacy(DataInputStream a) {
//		GameMap answer = new GameMap();
//		answer.loadLegacy2(a);
//		return answer;
//	}
//
//	/**
//	 * Load from a legacy map file.
//	 * 
//	 * @param di
//	 *            Stream to load from.
//	 */
//	private void loadLegacy2(DataInputStream di) {
//		try {
//			 // Undo the trick whereby the first word is the length in bytes and the
//			 // final word is the first word (moved there to make room for the length in
//			 // bytes ... before the entire block of memory was saved to disk).
//			int firstWord = di.readUnsignedShort();
//			assert (firstWord & 1) == 0;
//			int length = firstWord / 2 - 1;
//			for (int x = 1; x < length;) {
//				map[x++] = (short) di.readUnsignedShort();
//			}
//			map[0] = (short) di.readUnsignedShort();
//			// unpack it
//			BinaryMapRle.unpack(map, length);
//		}
//		catch (IOException e) {
//			throw new RuntimeException(e);
//		}
//	}

	public int fastGetBlock(int x, int y) {
		return map[y][x];
	}
	
	public void fastSetBlock(int x, int y, int b) {
		map[y][x] = (short) b;
	}

	public int getBlock(Coord c) {
		return fastGetBlock(c.x, c.y);
	}

	public void setBlock(Coord c, int b) {
		fastSetBlock(c.x, c.y, b);
	}

	public int safeGetBlock(Coord c) {
		if (!isInMap(c.x, c.y)) return 0;
		return getBlock(c);
	}


	private boolean isInMap(int x, int y) {
		return x >= 0 && x < w && y >= 0 && y < h;
	}

	public void applyShuffle(BlockAliasTable bat) {
		for (int y=0; y<h; y++) {
			for (int x=0; x<w; x++) {
				fastSetBlock(x, y, bat.shuffle(fastGetBlock(x, y)));
			}
		}
	}

	public void applyCompress(BlockAliasTable bat) {
		for (int y=0; y<h; y++) {
			for (int x=0; x<w; x++) {
				fastSetBlock(x, y, bat.compress(fastGetBlock(x, y)));
			}
		}
	}

	public static GameMap load(Node a) {
		GameMap answer = new GameMap(OMAP_WIDTH, OMAP_HEIGHT);
		answer.load2(a);
		return answer;
	}

	private void load2(Node di) {
		for (int y = 0; y < OMAP_HEIGHT; y++) {
			TextMapRle.unpack(map[y], 0, OMAP_WIDTH, di.requireElement(y).requireString());
		}
	}

	public void save(DataDestination dd) {
		for (int y = 0; y < h; y++) {
			dd.write(TextMapRle.pack(map[y], 0, w));
		}
	}
}
