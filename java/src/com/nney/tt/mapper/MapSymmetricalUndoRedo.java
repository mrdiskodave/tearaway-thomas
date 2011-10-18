package com.nney.tt.mapper;

import com.nney.tt.map.GameMap;

public class MapSymmetricalUndoRedo extends SymmetricalUndoRedo {
	private final GameMap gameMap;
	private final int top;
	private final int left;
	private SaveMapBlock sbm;

	public MapSymmetricalUndoRedo(GameMap gameMap, int x, int y, SaveMapBlock smb) {
		this.gameMap = gameMap;
		this.sbm = smb;
		top = y;
		left = x;
	}

	@Override
	public void swap() {
		sbm.swap(left, top, gameMap);
	}

	public boolean changesNothing() {
		return sbm.compare(left, top, gameMap);
	}
}
