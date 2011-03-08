package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class GameMap {
	final static public int MAP_WIDTH = 256;
	final static public int MAP_HEIGHT = 128;
	final static public int MAP_SIZE = MAP_WIDTH*MAP_HEIGHT;
	final private short[] map = new short[MAP_SIZE];

	int get_word(byte[] x, int o) {
		return x[o] * 256 + x[o + 1];
	}

	public GameMap(Openable src) {
		byte[] level = OpenableTools.load(src);

		// copy it in
		int se = get_word(level, 0);
		assert (se & 1) == 0;
		se >>= 1;
		for (int x = 0; x < se; x++) {
			map[x] = (short) get_word(level, x * 2);
		}

		// fix it up
		--se;
		map[0] = map[se];
		// unpack it in situe
		int de = 0x8000;
		while (se != 0) {
			// read the next value
			--se;
			int x = map[se];
			// what is it?
			int r;
			if ((x & 0x8000) != 0) {
				// it is either got the top bit set in which case
				// NOT it for the block number
				x ^= 0xffff;
				// and the next word is a repeat count
				--se;
				r = map[se] + 1;
			}
			else {
				// or it hasn't in which case it is a regular block repeated once 
				r = 1;
			}
			// output the block
			do {
				--de;
				map[de] = (short) x;
			} while (--r > 0);
		}
	}
	
	int getBlock(int x, int y) {
		if (x<0 || x>=MAP_WIDTH || y<0 || y>=MAP_HEIGHT) return 0;
		return map[y*MAP_WIDTH+x];
	}
}
