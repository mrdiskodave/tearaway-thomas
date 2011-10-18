package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class SaveMapBlock {
	private final short[][] z;
	public final int w;
	public final int h;

	private SaveMapBlock(int w, int h) {
		this.w = w;
		this.h = h;
		this.z = new short[h][w];
	}

	public static SaveMapBlock fromMap(Box rectangle, GameMap gameMap) {
		SaveMapBlock answer = new SaveMapBlock(rectangle.width(), rectangle.height());
		answer.read(rectangle.topLeft(), gameMap);
		return answer;
	}
	
	public static SaveMapBlock fromSolid(int w, int h, int b) {
		SaveMapBlock answer = new SaveMapBlock(w, h);
		answer.fill(b);
		return answer;
	}

	private int get(int x, int y) {
		return z[y][x];
	}

	private void set(int x, int y, int s) {
		z[y][x] = (short) s;
	}
	
	private void read(Coord mapPos, GameMap gameMap) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord m = mapPos.copyAndAdd(x, y);
				set(x, y, gameMap.getBlock(m));
			}
		}
	}
	
	public boolean eorUs(Coord mapPos, GameMap gameMap) {
		int r = 0;
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord m = mapPos.copyAndAdd(x, y);
				int ea = gameMap.getBlock(m)^get(x, y);
				set(x, y, ea);
				r |= ea;
			}
		}
		return r != 0;
	}
	
	public void eorMap(Coord mapPos, GameMap gameMap) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord m = mapPos.copyAndAdd(x, y);
				int ea = gameMap.getBlock(m)^get(x, y);
				gameMap.setBlock(m, ea);
			}
		}
	}
	
	public SaveMapBlock copy() {
		SaveMapBlock answer = new SaveMapBlock(w, h);
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				answer.set(x, y, get(x, y));
			}
		}
		return answer;
	}

	public void fill(int currentBlock) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				set(x, y, currentBlock);
			}
		}
	}

//	public void dump() {
//		for (int y = 0; y < h; y++) {
//			StringBuffer sb = new StringBuffer();
//			for (int x = 0; x < w; x++) {
//				if (x!=0) sb.append(',');
//				sb.append(get(x, y));
//			}
//			System.out.println(sb);
//		}
//	}

}
