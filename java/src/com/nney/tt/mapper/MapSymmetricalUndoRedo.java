package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.map.GameMap;

public class MapSymmetricalUndoRedo extends SymmetricalUndoRedo {
	private final GameMap gameMap;
	private final int top;
	private final int left;
	private SaveMapBlock sbm;

	// For capturing an edit box before we strip it off the screen then Redo it
	public MapSymmetricalUndoRedo(GameMap gameMap, Box b) {
		this.gameMap = gameMap;
		this.sbm = new SaveMapBlock(b.width(), b.height());
		top = b.top;
		left = b.left;
		read();
	}
	
	// For Pasting a saved box
	public MapSymmetricalUndoRedo(GameMap gameMap, int x, int y, SaveMapBlock savedBoxForPasting) {
		this.gameMap = gameMap;
		this.sbm = savedBoxForPasting.copy();
		top = y;
		left = x;
	}

	@Override
	public void swap() {
		sbm.swap(left, top, gameMap);
	}

	private void read() {
		sbm.read(left, top, gameMap);
	}
	
	public boolean changesNothing() {
		return sbm.compare(left, top, gameMap);
	}
}
