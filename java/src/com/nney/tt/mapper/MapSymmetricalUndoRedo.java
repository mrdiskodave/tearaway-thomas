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
		process(true, false);
	}
	
	// For Pasting a saved box
	public MapSymmetricalUndoRedo(GameMap gameMap, int x, int y, SaveMapBlock sbm) {
		this.gameMap = gameMap;
		this.sbm = sbm.copy();
		top = y;
		left = x;
	}

	@Override
	public void swap() {
		process(true, true);
	}

	private void process(boolean read, boolean write) {
		sbm.process(read, write, left, top, gameMap);
	}
	
	public boolean changesNothing() {
		return sbm.compare(left, top, gameMap);
	}
}
