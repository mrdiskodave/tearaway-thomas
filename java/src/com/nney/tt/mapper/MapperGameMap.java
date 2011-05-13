package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Stack;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.MapperGameMap.Undo;

class MapperGameMap {
	private final GameMap gameMap;

	private ArrayList<Event> events = new ArrayList<Event>();

	private Stack<Undo> undo = new Stack<Undo>();
	
	private Stack<Undo> redo = new Stack<Undo>();
	
	class Undo {
		int top;
		int left;
		short[][] what;
		private String str;

		Undo(Box b) {
			top = b.top;
			left = b.left;
			int h = b.height();
			int w = b.width();
			what = new short[h][w];
			str = "Undo for "+b;
			read(false);
		}
		
		void read(boolean swap) {
			for (int y=0; y<what.length; y++) {
				for (int x=0; x<what[y].length; x++) {
					Coord mapCoord = new Coord(left+x, top+y);
					Coord whatCoord = new Coord(x, y);
					int m = gameMap.getBlock(mapCoord);
					if (swap) {
						gameMap.setBlock(mapCoord, what[whatCoord.y][whatCoord.x]);
					}
					what[whatCoord.y][whatCoord.x] = (short) m;
				}
			}
		}
		
		@Override
		public String toString() {
			return str;
		}
		
	}
	
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
		Undo u = new Undo(b);
		undo.push(u);
		System.out.println("saved"+u);
	}
	
	public void undo() {
		if (!undo.isEmpty()) {
			Undo u = undo.pop();
			u.read(true);
			redo.push(u);
		}
	}

	public void redo() {
		if (!redo.isEmpty()) {
			Undo u = redo.pop();
			u.read(true);
			undo.push(u);
		}
	}
	
}
