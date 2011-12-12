package com.nney.tt.map;

import java.util.Iterator;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.utils.ReadOnlyIterator;

public final class GameMap implements Iterable<Coord> {
	// use of these private constants are the only place
	// where map size is still hard-wired
	private final static int OMAP_WIDTH = 256;
	private final static int OMAP_HEIGHT = 128;
	// this opens up the possibility of megamaps!!!
	private static final Box DEFAULT_BOUNDS = Box.fromTopLeftAndSize(0, 0, OMAP_WIDTH, OMAP_HEIGHT);

	private final Box boundsInPixels;

	private final short[][] map;
	private final int ax;
	private final int ay;
	private final int w;
	private final int h;
	private Coord topLeft;
	private Box boundsInBlocks;

	public Box boundsInBlocks() {
		return boundsInBlocks;
	}

	public GameMap() {
		this(DEFAULT_BOUNDS);
	}

	public GameMap(Box boundsInBlocks) {
		this.boundsInBlocks = boundsInBlocks;
		boundsInPixels = boundsInBlocks.mult2(Const.BLOCK_SIZE);

		this.topLeft = boundsInBlocks.topLeft();
		this.w = boundsInBlocks.width();
		this.h = boundsInBlocks.height();
		this.ax = -topLeft.x;
		this.ay = -topLeft.y;
		map = new short[h][w];
	}

	public GameMap(Box boundsInBlocks, GameMap oldMap) {
		this(boundsInBlocks);
		for (Coord c : this) {
			setBlock(c, oldMap.safeGetBlock(c));
		}
	}

	public Box boundsInPixels() {
		return boundsInPixels;
	}

	// public static GameMap loadLegacy(DataInputStream a) {
	// GameMap answer = new GameMap();
	// answer.loadLegacy2(a);
	// return answer;
	// }
	//
	// /**
	// * Load from a legacy map file.
	// *
	// * @param di
	// * Stream to load from.
	// */
	// private void loadLegacy2(DataInputStream di) {
	// try {
	// // Undo the trick whereby the first word is the length in bytes and the
	// // final word is the first word (moved there to make room for the length
	// in
	// // bytes ... before the entire block of memory was saved to disk).
	// int firstWord = di.readUnsignedShort();
	// assert (firstWord & 1) == 0;
	// int length = firstWord / 2 - 1;
	// for (int x = 1; x < length;) {
	// map[x++] = (short) di.readUnsignedShort();
	// }
	// map[0] = (short) di.readUnsignedShort();
	// // unpack it
	// BinaryMapRle.unpack(map, length);
	// }
	// catch (IOException e) {
	// throw new RuntimeException(e);
	// }
	// }

	public int fastGetBlock(int x, int y) {
		return map[ay + y][ax + x];
	}

	public void fastSetBlock(int x, int y, int b) {
		map[ay + y][ax + x] = (short) b;
	}

	private boolean isInMap(int x, int y) {
		x += ax;
		y += ay;
		return x >= 0 && x < w && y >= 0 && y < h;
	}

	public int getBlock(Coord c) {
		return fastGetBlock(c.x, c.y);
	}

	public void setBlock(Coord c, int b) {
		fastSetBlock(c.x, c.y, b);
	}

	public int safeGetBlock(int x, int y) {
		if (!isInMap(x, y)) return 0;
		return fastGetBlock(x, y);
	}

	public int safeGetBlock(Coord c) {
		return safeGetBlock(c.x, c.y);
	}

	public interface BlockFunc {
		int update(int x);
	}

	public void apply(BlockFunc func) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				int gx = x - ax;
				int gy = y - ay;
				fastSetBlock(gx, gy, func.update(fastGetBlock(gx, gy)));
			}
		}
	}

	public static GameMap load(Node a) {
		int version = 0;
		if (a.fieldExists("version")) {
			version = a.requireField("version").requireInt();
		}
		Box bounds = DEFAULT_BOUNDS;
		Node content = a;
		if (version >= 1) {
			bounds = Box.load(a.requireField("place"));
			content = a.requireField("content");
		}
		GameMap answer = new GameMap(bounds);
		answer.load2(content);
		return answer;
	}

	private void load2(Node di) {
		for (int y = 0; y < h; y++) {
			TextMapRle.unpack(map[y], 0, w, di.requireElement(y).requireString());
		}
	}

	public void save(DataDestination dd) {
		dd.beginObject();
		dd.write("version");
		dd.write(1);
		dd.write("place");
		boundsInBlocks.save(dd);
		dd.write("content");
		dd.beginArray();
		for (int y = 0; y < h; y++) {
			dd.write(TextMapRle.pack(map[y], 0, w));
		}
		dd.end();
		dd.end();
	}

	public int width() {
		return w;
	}

	public int height() {
		return h;
	}

	public int area() {
		return w * h;
	}

	@Override
	public Iterator<Coord> iterator() {
		final int s = area();
		return new ReadOnlyIterator<Coord>() {
			int z;

			@Override
			public boolean hasNext() {
				return z < s;
			}

			@Override
			public Coord next() {
				return generate(z++);
			}
		};
	}

	public Coord move(Coord coord) {
		return coord.add2(topLeft);
	}

	public Coord generate(int z) {
		int x = z % w;
		int y = z / w;
		return new Coord(x - ax, y - ay);
	}

	public int ungenerate(Coord c) {
		int x = c.x + ax;
		int y = c.y + ay;
		return y * w + x;
	}

}
