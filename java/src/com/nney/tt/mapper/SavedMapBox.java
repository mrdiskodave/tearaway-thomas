package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.map.GameMap;

public class SavedMapBox extends SymmetricalUndoRedo {
	private final GameMap gameMap;
	private final int top;
	private final int left;
	private SBM sbm;

	// for capturing an edit box before we strip it off the screen then Redo it
	public SavedMapBox(GameMap gameMap, Box b) {
		this.gameMap = gameMap;
		this.sbm = new SBM(b.width(), b.height());
		top = b.top;
		left = b.left;
		process(true, false);
	}
	
	// for Pasting a saved box
	public SavedMapBox(GameMap gameMap, int x, int y, SBM sbm) {
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
}
