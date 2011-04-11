package com.nney.tt.map;

public class MapRle {

	public static void unpack(short[] map, int length) {
		int s = length;

		// unpack it in situe
		int d = map.length;
		while (s != 0) {
			// read the next value
			int x = map[--s];
			// what is it?
			int r;
			if ((x & 0x8000) != 0) {
				// it is either got the top bit set in which case
				// NOT it for the block number
				x ^= 0xffff;
				// and the next word is a repeat count
				r = (map[--s]&0xffff) + 1;
			}
			else {
				// or it hasn't in which case it is a regular block number
				// (repeated once)
				r = 1;
			}
			// output the block
//			System.out.println(String.format("U src=%04x dest=%04x repeat=%04x value=%04x", s, d, r, x&0xffff));
			do {
				map[--d] = (short) x;
			} while (--r > 0);
		}
		assert d == 0 : d;
	}

	public static int pack(short[] map) {
		int s = 0;
		int d = 0;
		while (s < map.length) {
			short x = map[s];
			int r = 1;
			for (;;) {
				int n = s + r;
				if (n >= map.length || map[n] != x) break;
				r++;
			}
//			System.out.println(String.format("P src=%04x dest=%04x repeat=%04x value=%04x", s, d, r, x&0xffff));
			if (r < 3) {
				for (int q=0; q<r; q++) {
					map[d++] = x;
				}
			}
			else {
				map[d++] = (short) (r - 1);
				map[d++] = (short) (x ^ 0xffff);
			}
			s += r;
		}
		assert s==map.length;
		return d;
	}

}
