package com.nney.tt.mapper;

import java.util.ArrayList;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

public class DrawingTool {
	private final ArrayList<Event> events = new ArrayList<Event>();
	private final GameMap gameMap;

	private class Event {
		final Coord where;
		int what;

		private Event(Coord where, int what) {
			this.where = where;
			this.what = what;
		}
	}
	
	public DrawingTool(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			events.add(new Event(c, existingBlock));
			gameMap.setBlock(c, block);
		}
	}

	private void swap(Event e) {
		int tmp = gameMap.getBlock(e.where);
		gameMap.setBlock(e.where, e.what);
		e.what = tmp;
	}

	public UndoRedo endEdit() {
		UndoRedo undo = null;
		if (events.size() != 0) {
			Box b = Box.around(events.get(0).where, 0, 0);
			for (Event e : events) {
				b.accommodate(e.where);
				swap(e);
			}
			System.out.println("Events: " + b);
			undo = new SavedMapBox(gameMap, b);
			for (Event e : events) {
				swap(e);
			}
		}
		events.clear();
		return undo;
	}
}
