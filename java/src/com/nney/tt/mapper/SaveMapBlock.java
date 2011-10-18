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
		answer.read(rectangle.left, rectangle.top, gameMap);
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
	
	public void read(int x, int y, GameMap gameMap) {
		process(true, false, x, y, gameMap);
	}

	public void swap(int x, int y, GameMap gameMap) {
		process(true, true, x, y, gameMap);
	}

	private void process(boolean read, boolean write, int left, int top, GameMap gameMap) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord mapCoord = new Coord(left + x, top + y);
				int mapBlock = gameMap.getBlock(mapCoord);
				int ourBlock = get(x, y);
				if (read) {
					set(x, y, mapBlock);
				}
				if (write) {
					gameMap.setBlock(mapCoord, ourBlock);
				}
			}
		}
	}
	
	public boolean compare(int left, int top, GameMap gameMap) {
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				Coord mapCoord = new Coord(left + x, top + y);
				int mapBlock = gameMap.getBlock(mapCoord);
				int ourBlock = get(x, y);
				if (mapBlock!=ourBlock) {
					return false;
				}
			}
		}
		return true;
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
