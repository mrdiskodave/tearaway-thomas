package com.nney.tt.mapper;

import java.util.ArrayList;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class EditConsolidator {
	private final ArrayList<Edit> edits = new ArrayList<Edit>();
	private final GameMap gameMap;

	private class Edit {
		final Coord where;
		int what;

		private Edit(Coord where, int what) {
			this.where = where;
			this.what = what;
		}
	}
	
	public EditConsolidator(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			edits.add(new Edit(c, existingBlock));
			gameMap.setBlock(c, block);
		}
	}

	private void swap(Edit e) {
		int tmp = gameMap.getBlock(e.where);
		gameMap.setBlock(e.where, e.what);
		e.what = tmp;
	}

	public UndoRedo endEdit() {
		UndoRedo undo = null;
		if (edits.size() != 0) {
			Box b = Box.around(edits.get(0).where, 0, 0);
			for (Edit e : edits) {
				b.accommodate(e.where);
				swap(e);
			}
			undo = new SavedMapBox(gameMap, b);
			for (Edit e : edits) {
				swap(e);
			}
		}
		edits.clear();
		return undo;
	}
}
