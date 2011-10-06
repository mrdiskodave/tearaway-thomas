package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.mapper.Mapper.CoordType;

abstract class Tool {

	private int level;
	private HashMap<Integer, Tool> nest = new HashMap<Integer, Tool>();

	protected Mapper srv;

	void drawBlockCursor() {
		// TODO Auto-generated method stub
		
	}


	public Tool(Mapper srv) {
		this.srv = srv;
	}


	protected void moreBusy() {
		level++;
//		System.out.println("MORE BUSY" + level);
	}

	protected void lessBusy() {
		assert level != 0;
		level--;
//		System.out.println("LESS BUSY" + level);
	}

	public boolean isFree() {
		return level == 0;
	}

	void addNested(int key, Tool tool) {
		nest.put(key, tool);
	}

	String name() {
		assert ownScreen();
		return null;
	}

	boolean ownScreen() {
		return false;
	}

	void presentation() {
	}

	abstract void run();

	void checkPushTool() {
	}

}
