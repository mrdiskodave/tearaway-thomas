package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class GameMap {
	final public static int MAP_WIDTH = 256;
	final public static int MAP_HEIGHT = 128;
	final public static int MAP_SIZE = MAP_WIDTH*MAP_HEIGHT;
	final private short[] map = new short[MAP_SIZE];

	private int get_word(byte[] x, int o) {
		int answer = x[o] & 255;
		answer<<= 8;
		answer |= x[o+1]&255;
		return answer;
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
		map[0] = map[--se];
		// unpack it in situe
		int de = 0x8000;
		while (se != 0) {
			// read the next value
			int x = map[--se];
			// what is it?
			int r;
			if ((x & 0x8000) != 0) {
				// it is either got the top bit set in which case
				// NOT it for the block number
				x ^= 0xffff;
				// and the next word is a repeat count
				r = map[--se] + 1;
			}
			else {
				// or it hasn't in which case it is a regular block number (repeated once) 
				r = 1;
			}
			// output the block
			System.out.println(String.format("src=%04x dest=%04x repeat=%04x value=%04x", se, de, r, x&0xffff));
			do {
				map[--de] = (short) x;
			} while (--r > 0);
		}
		assert de==0 : de;
	}
	
	public int getBlock(int x, int y) {
		if (x<0 || x>=MAP_WIDTH || y<0 || y>=MAP_HEIGHT) return 0;
		return map[y*MAP_WIDTH+x];
	}
}
