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
		load(di);
		unpack();
	}

	private void load(DataInputStream di) throws IOException {
		int firstWord = di.readUnsignedShort();
		assert (firstWord & 1) == 0;
		length = firstWord >>= 1;
		for (int x = 1; length != x;) {
			map[x++] = (short) di.readUnsignedShort();
		}
	}

	public void unpack() {
		int compressedMapWords = length;
		
		// fix it up
		// (the first word can be found on the end ...
		// we stuck it there so we could put the length in the first word
		// without shuffling stuff about in memory too much)
		map[0] = map[--compressedMapWords];
		
		// unpack it in situe
		int unpackPtr = MAP_SIZE;
		while (compressedMapWords != 0) {
			// read the next value
			int x = map[--compressedMapWords];
			// what is it?
			int r;
			if ((x & 0x8000) != 0) {
				// it is either got the top bit set in which case
				// NOT it for the block number
				x ^= 0xffff;
				// and the next word is a repeat count
				r = map[--compressedMapWords] + 1;
			}
			else {
				// or it hasn't in which case it is a regular block number
				// (repeated once)
				r = 1;
			}
			// output the block
			// System.out.println(String.format("src=%04x dest=%04x repeat=%04x value=%04x",
			// compressedMapWords, unpackPtr, r, x&0xffff));
			do {
				map[--unpackPtr] = (short) x;
			} while (--r > 0);
		}
		assert unpackPtr == 0 : unpackPtr;
	}
	
	public void pack() {
		int s = 0;
		int d = 0;
		while (s<MAP_SIZE) {
			short x = map[s];
			int r = 1;
			for (;;) {
				int n = s+r;
				if (n>=MAP_SIZE || map[n]!=x) break;
				r++;
			}
			if (r<3) {
				map[d++] = x; 
			}
			else {
				map[d++] = (short) (r-1);
				map[d++] = (short) (x ^ 0xffff);
			}
		}
		
		// put the length on the start
		// (making room by moving the first word to the end)
		short temp = map[0];
		map[d++] = temp;
		map[0] = (short) d;
	}

	public int getBlock(int x, int y) {
		// assert x < 0;
		// assert x >= MAP_WIDTH;
		// assert y < 0;
		// assert y >= MAP_HEIGHT;
		if (x < 0)
			return 0;
		if (x >= MAP_WIDTH)
			return 0;
		if (y < 0)
			return 0;
		if (y >= MAP_HEIGHT)
			return 0;
		return map[y * MAP_WIDTH + x];
	}

	public void applyRt(BlockRandomisationTable rt) {
		StopWatch sw = new StopWatch();
		for (int x = 0; x < map.length; x++) {
			map[x] = (short) rt.shuffle(map[x]);
		}
		System.out.println("Shuffle took " + sw.readMsf() + "ms");
	}
}
