package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map.Entry;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

/**
 * Collects up a number of {@link #setBlock(Coord, int, boolean)} events to make a
 * single {@link MapSymmetricalUndoRedo} object.
 */
public class EditConsolidator {
	private final HashMap<Coord, Integer> originalBlocks = new HashMap<Coord, Integer>();
	private final GameMap gameMap;

	public EditConsolidator(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	/**
	 * Change a block.
	 * 
	 * @param c Where is the block to change?
	 * @param block What do you want to change it to?
	 * @param always 
	 * <code>false</code> meaning "only store this edit if it has an effect".
	 * <code>true</code> meaning "always store this edit even if it has no effect".
	 */
	public void setBlock(Coord c, int block, boolean always) {
		int existingBlock = gameMap.getBlock(c);
		if (always || block != existingBlock) {
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

	public boolean isChangeAt(Coord s) {
		return originalBlocks.containsKey(s);
	}
	
	public int size() {
		return originalBlocks.size();
	}
}
