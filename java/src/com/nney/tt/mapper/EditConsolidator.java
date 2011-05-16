package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class EditConsolidator implements EditDestination {
	private final HashMap<Coord, Integer> edits = new HashMap<Coord, Integer>();
	private final GameMap gameMap;

	public EditConsolidator(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	@Override
	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			edits.put(c, existingBlock);
			gameMap.setBlock(c, block);
		}
	}

	private void swap(Coord c) {
		int tmp = gameMap.getBlock(c);
		gameMap.setBlock(c, edits.get(c));
		edits.put(c, tmp);
	}

	public UndoRedo endEdit() {
		UndoRedo undo = null;
		if (edits.size() != 0) {
			Box b = null;
			System.out.println("undo");
			for (Coord c : edits.keySet()) {
				if (b==null) {
					b = Box.around(c);
				}
				else {
					b.accommodate(c);
				}
				swap(c);
			}
			System.out.println("capture:"+b);
			undo = new SavedMapBox(gameMap, b);
			System.out.println("redo");
			for (Coord c : edits.keySet()) {
				swap(c);
			}
			System.out.println("Ended.");
		}
		edits.clear();
		return undo;
	}
}
