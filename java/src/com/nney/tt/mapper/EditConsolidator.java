package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map.Entry;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class EditConsolidator implements EditDestination {
	private final HashMap<Coord, Integer> originalBlocks = new HashMap<Coord, Integer>();
	private final GameMap gameMap;

	public EditConsolidator(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	@Override
	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			originalBlocks.put(c, existingBlock);
			gameMap.setBlock(c, block);
		}
	}

	public MapSymmetricalUndoRedo endEdit() {
		MapSymmetricalUndoRedo undo = null;
		Box b = sizeUpEdits();
		if (b != null) {
			System.out.println("SAVING");
			undo = new MapSymmetricalUndoRedo(gameMap, b);
			System.out.println("SAVED");
			for (Entry<Coord, Integer> kv : originalBlocks.entrySet()) {
				gameMap.setBlock(kv.getKey(), kv.getValue());
			}
		}
		originalBlocks.clear();
		return undo;
	}

	private Box sizeUpEdits() {
		Box b = null;
		for (Coord c : originalBlocks.keySet()) {
			if (b == null) {
				b = Box.around(c);
			}
			else {
				b.accommodate(c);
			}
		}
		return b;
	}
}
