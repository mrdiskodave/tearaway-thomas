package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Stack;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;

class MapperGameMap {
	private final GameMap gameMap;


	private Stack<SavedMapBox> undo = new Stack<SavedMapBox>();
	
	private Stack<SavedMapBox> redo = new Stack<SavedMapBox>();

	
	
	
	// edits in a row
	
	private ArrayList<Event> events = new ArrayList<Event>();
	
	class Event {
		final Coord where;
		int what;

		Event(Coord where, int what) {
			this.where = where;
			this.what = what;
		}
	}
	public void setBlock(Coord c, int block) {
		int existingBlock = gameMap.getBlock(c);
		if (block != existingBlock) {
			events.add(new Event(c, existingBlock));
			gameMap.setBlock(c, block);
			System.out.println("Set: "+c);
		}
	}

	private void swap(Event e) {
		int tmp = gameMap.getBlock(e.where);
		gameMap.setBlock(e.where, e.what);
		e.what = tmp;
	}


	
	
	
	
	
	
	MapperGameMap(GameMap gameMap) {
		this.gameMap = gameMap;
	}


	public void endEdit() {
		if (events.size()!=0) {
			System.out.println("End edit");
			Box b = Box.around(events.get(0).where, 1, 1);
			for (Event e: events) {
				swap(e);
				b.accommodate(e.where);
			}
			System.out.println("Events: "+b);
			saveUndo(b);
			for (Event e: events) {
				swap(e);
			}
		}
		events.clear();
	}

	private void saveUndo(Box b) {
		SavedMapBox u = new SavedMapBox(gameMap, b);
		undo.push(u);
		System.out.println("saved"+u);
	}
	
	public void undo() {
		if (!undo.isEmpty()) {
			SavedMapBox u = undo.pop();
			u.swap(gameMap);
			redo.push(u);
		}
	}

	public void redo() {
		if (!redo.isEmpty()) {
			SavedMapBox u = redo.pop();
			u.swap(gameMap);
			undo.push(u);
		}
	}
	
}
