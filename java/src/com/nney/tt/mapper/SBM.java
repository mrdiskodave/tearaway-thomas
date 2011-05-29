package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class SBM {
	private final short[][] z;
	public final int w;
	public final int h;

	public SBM(int w, int h) {
		this.w = w;
		this.h = h;
		this.z = new short[h][w];
	}

	public int get(int x, int y) {
		return z[y][x];
	}

	public void set(int x, int y, int s) {
		z[y][x] = (short) s;
	}

	public void process(boolean read, boolean write, int left, int top, GameMap gameMap) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord mc = new Coord(left + x, top + y);
				int wm = get(x, y);
				int rm = gameMap.getBlock(mc);
				if (read) {
					set(x, y, rm);
				}
				if (write) {
					gameMap.setBlock(mc, wm);
				}
			}
		}
	}
	
	public SBM copy() {
		SBM answer = new SBM(w, h);
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				answer.set(x, y, get(x, y));
			}
		}
		return answer;
	}
	
	public void dump() {
		for (int y = 0; y < h; y++) {
			StringBuffer sb = new StringBuffer();
			for (int x = 0; x < w; x++) {
				if (x!=0) sb.append(',');
				sb.append(get(x, y));
			}
			System.out.println(sb);
		}
	}
}
