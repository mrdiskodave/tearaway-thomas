package com.nney.tt.map;

import java.io.DataInputStream;
import java.io.IOException;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.geom.Coord;

public class GameMap {
	final public static int MAP_WIDTH = 256;
	final public static int MAP_HEIGHT = 128;
	final public static int MAP_SIZE = MAP_WIDTH * MAP_HEIGHT;
	final private short[] map = new short[MAP_SIZE];

	/**
	 * Load from a legacy map file.
	 * 
	 * Undo the trick whereby the first word is the length in bytes and the
	 * final word is the first word (moved there to make room for the length in
	 * bytes ... before the entire block of memory was saved to disk).
	 * 
	 * @param di
	 *            Stream to load from.
	 * @throws IOException
	 */
	public void loadFromLegacyMap(DataInputStream di) throws IOException {
		int firstWord = di.readUnsignedShort();
		assert (firstWord & 1) == 0;
		int length = firstWord / 2 - 1;
		for (int x = 1; x < length;) {
			map[x++] = (short) di.readUnsignedShort();
		}
		map[0] = (short) di.readUnsignedShort();
		BinaryMapRle.unpack(map, length);
	}
	
	public int fastGetBlock(int x, int y) {
		assert isInMap(x, y);
		return map[y * MAP_WIDTH + x];
	}

	private int mapOffset(Coord c) {
		return c.y * MAP_WIDTH + c.x;
	}

	public int getBlock(Coord c) {
		validPosition(c.x, c.y);
		short answer = map[mapOffset(c)];
//		System.out.println("Get " + c + " is " + answer);
		return answer;
	}
	
	public int safeGetBlock(Coord c) {
		if (!isInMap(c.x, c.y)) return 0;
		return getBlock(c);
	}

	public void setBlock(Coord c, int b) {
		validPosition(c.x, c.y);
//		System.out.println("Set " + c + " to " + b);
		map[mapOffset(c)] = (short) b;
	}

	private void validPosition(int x, int y) {
		if (!isInMap(x, y)) {
			throw new RuntimeException(x+"x"+y+" is outside the map");
		}
	}


	private boolean isInMap(int x, int y) {
		return (x >= 0 && x < MAP_WIDTH && y >= 0 && y < MAP_HEIGHT);
	}

	public void applyShuffle(BlockAliasTable bat) {
		for (int x = 0; x < map.length; x++) {
			map[x] = (short) bat.shuffle(map[x]);
		}
	}

	public void applyCompress(BlockAliasTable bat) {
		for (int x = 0; x < map.length; x++) {
			map[x] = (short) bat.compress(map[x]);
		}
	}

	public void saveMap(DataDestination dd) {
		for (int y=0; y<MAP_HEIGHT; y++) {
			dd.write(TextMapRle.pack(map, y*MAP_WIDTH, MAP_WIDTH));
		}
	}
	
	public void loadMap(DataItem di) {
		for (int y=0; y<MAP_HEIGHT; y++) {
			TextMapRle.unpack(map, y*MAP_WIDTH, MAP_WIDTH, di.requireElement(y).requireString());
		}
	}
}
