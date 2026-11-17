package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map.Entry;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

/**
 * Collects up a number of {@link #setBlock(Coord, int)} events to make a single
 * {@link MapEdit} object.
 */
public class EditConsolidator {
	private final HashMap<Coord, Integer> originalBlocks = new HashMap<>();
	private final GameMap gameMap;

	public EditConsolidator(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	/**
	 * Change a block.
	 * 
	 * @param c
	 *            Where is the block to change? Subsequent changes at this
	 *            location will be ignored. So, essentially, this class is only
	 *            useful for creating edits that paint a fixed block (or block
	 *            pattern).
	 * @param b
	 *            What should it be changed to?
	 */
	public void setBlock(Coord c, int b) {
		if (!isChangeAt(c)) {
			int originalBlock = gameMap.getBlock(c);

			// when drawing we could save the need for this
			// when b==originalBlock
			// (because drawing doesn't need isChangeAt() to work)
			// then we'd save some memory but this whole
			// object is very temporary anyway so meh

			originalBlocks.put(c, originalBlock);
			gameMap.setBlock(c, b);
		}
	}

	public MapEdit endEdit() {
		MapEdit answer = MapEdit.createEmpty();
		Box b = sizeUpEdits();
		if (b != null) {
			System.out.println("SAVING");
			SavedMapBlock sb = SavedMapBlock.fromMap(b, gameMap);
			System.out.println("SAVED");
			for (Entry<Coord, Integer> kv : originalBlocks.entrySet()) {
				gameMap.setBlock(kv.getKey(), kv.getValue());
			}
			answer = MapEdit.create(gameMap, b.topLeft(), sb);
		}
		originalBlocks.clear();
		return answer;
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

	/**
	 * Have we called {@link #setBlock(Coord, int)} on a location?
	 * 
	 * @param c
	 *            The location.
	 * @return <code>true</code> meaning "we have" or <code>false</code> meaning
	 *         "we have not".
	 */
	public boolean isChangeAt(Coord c) {
		return originalBlocks.containsKey(c);
	}

	/**
	 * How many blocks did we change?
	 * 
	 * @return The number calls made to {@link #setBlock(Coord, int)}.
	 */
	public int size() {
		return originalBlocks.size();
	}
}
