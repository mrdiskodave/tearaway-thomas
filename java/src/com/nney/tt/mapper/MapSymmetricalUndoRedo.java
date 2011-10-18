package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class MapSymmetricalUndoRedo extends SymmetricalUndoRedo {
	private final GameMap gameMap;
	private final Coord c;
	private final SaveMapBlock smb;
	
	private MapSymmetricalUndoRedo(GameMap gameMap, Coord c, SaveMapBlock smb) {
		this.gameMap = gameMap;
		this.smb = smb;
		this.c = c;
	}


	static MapSymmetricalUndoRedo create(GameMap gameMap, Coord c, SaveMapBlock smb) {
		if (!smb.eorUs(c, gameMap)) return null;
		
		// smb is now immutable. we only ever call eorMap() on it.
		// for many edits it will be mostly zeros.
		// we could gzip it or who knows what, making us more efficient on undo/redo space.
		return new MapSymmetricalUndoRedo(gameMap, c, smb);
	}

	@Override
	public void swap() {
		smb.eorMap(c, gameMap);
	}
}
