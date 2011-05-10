package com.nney.tt.map;

import java.io.DataInputStream;
import java.io.IOException;

import com.nney.tt.StopWatch;

public class GameMap {
	final public static int MAP_WIDTH = 256;
	final public static int MAP_HEIGHT = 128;
	final public static int MAP_SIZE = MAP_WIDTH * MAP_HEIGHT;
	final private short[] map = new short[MAP_SIZE];
	private int length;

	public GameMap(DataInputStream di) throws IOException {
		loadFromLegacyMap(di);
		unpack();
	}

	/**
	 * Load from a legacy map file.
	 * 
	 * Undo the trick whereby the first word is the length in bytes and the
	 * final word is the first word (moved there to make room for the length in
	 * bytes ... before the entire block of memory was saved to disk).
	 * 
	 * @param di Stream to load from.
	 * @throws IOException
	 */
	private void loadFromLegacyMap(DataInputStream di) throws IOException {
		int firstWord = di.readUnsignedShort();
		assert (firstWord & 1) == 0;
		length = firstWord / 2 - 1;
		for (int x = 1; x < length;) {
			map[x++] = (short) di.readUnsignedShort();
		}
		map[0] = (short) di.readUnsignedShort();
	}

	public void unpack() {
		System.out.println("Unpacking "+length);
		MapRle.unpack(map, length);
	}

	public void pack() {
		length = MapRle.pack(map);
		System.out.println("Packed to "+length);
	}

	public int getBlock(int x, int y) {
		boolean valid = x >= 0 && x < MAP_WIDTH && y >= 0 && y < MAP_HEIGHT;
//		if (!valid) return 0;
		assert valid : String.format("%d,%d", x, y);
		return map[y * MAP_WIDTH + x];
	}

	public void setBlock(int x, int y, int b) {
		assert x >= 0 && x < MAP_WIDTH && y >= 0 && y < MAP_HEIGHT;
		map[y * MAP_WIDTH + x] = (short) b;
	}

	
	public void applyShuffle(BlockAliasTable bat) {
		StopWatch sw = new StopWatch();
		for (int x = 0; x < map.length; x++) {
			map[x] = (short) bat.shuffle(map[x]);
		}
		System.out.println("Shuffle took " + sw.readMsf() + "ms");
	}
}
