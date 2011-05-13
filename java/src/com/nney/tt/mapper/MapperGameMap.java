package com.nney.tt.mapper;

import java.util.ArrayList;

import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

class MapperGameMap {
	private final GameMap gameMap;

	private ArrayList<Event> events = new ArrayList<Event>();
	private int undoCursor;

	class Event {
		final Coord where;
		int what;

		Event(Coord where, int what) {
			this.where = where;
			this.what = what;
		}
	}

	MapperGameMap(GameMap gameMap) {
		this.gameMap = gameMap;
	}

	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			while (events.size() > undoCursor) {
				events.remove(events.size() - 1);
			}
			events.add(new Event(c, existingBlock));
			undoCursor++;
			gameMap.setBlock(c, block);
		}
	}

	private void swap() {
		Event e = events.get(undoCursor);
		int tmp = gameMap.getBlock(e.where);
		gameMap.setBlock(e.where, e.what);
		e.what = tmp;
	}

	boolean undo() {
		if (undoCursor != 0) {
			undoCursor--;
			swap();
			return true;
		}
		return false;
	}

	boolean redo() {
		if (undoCursor < events.size()) {
			swap();
			undoCursor++;
			return true;
		}
		return false;
	}
}
