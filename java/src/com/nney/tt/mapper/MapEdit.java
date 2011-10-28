package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class MapEdit extends SymmetricalUndoRedo {
	private final GameMap gameMap;
	private final Coord c;
	private final SavedMapBlock smb;
	
	private MapEdit(GameMap gameMap, Coord c, SavedMapBlock smb) {
		this.gameMap = gameMap;
		this.smb = smb;
		this.c = c;
	}


	static MapEdit create(GameMap gameMap, Coord c, SavedMapBlock smb) {
		smb.eorUs(c, gameMap);
		
		// smb is now immutable. we only ever call eorMap() on it.
		// for many edits it will be mostly zeros.
		// we could gzip it or who knows what, making us more efficient on undo/redo space.
		return new MapEdit(gameMap, c, smb);
	}

	@Override
	public boolean swap() {
		return smb.eorMap(c, gameMap);
	}
}
