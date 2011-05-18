package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class SavedMapBox implements DoUndo {
	private final int top;
	private final int left;
	private final short[] what;
	private final int width;
	private final GameMap gameMap;

	public SavedMapBox(GameMap gameMap, Box b) {
		this.gameMap = gameMap;
		top = b.top;
		left = b.left;
		int h = b.height();
		int w = b.width();
		what = new short[w * h];
		width = w;
		read();
	}

	public void read() {
		process(true, false);
	}

	public void write() {
		process(false, true);
	}

	@Override
	public void undo() {
		swap();
	}

	public void swap() {
		process(true, true);
	}

	@Override
	public void redo() {
		swap();
	}

	private void process(boolean read, boolean write) {
		int pos = 0;
		int y = 0;
		while (pos < what.length) {
			for (int x = 0; x < width; x++) {
				Coord mapCoord = new Coord(left + x, top + y);
				int m = gameMap.getBlock(mapCoord);
				if (write) {
					gameMap.setBlock(mapCoord, what[pos]);
				}
				if (read) {
					what[pos] = (short) m;
				}
				pos++;
			}
			y++;
		}
		// System.out.println(String.format("%s %s blocks", swap ? "Swapped" :
		// "Saved", pos));
	}
}
