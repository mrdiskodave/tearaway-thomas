package com.nney.tt.mapper;

import java.util.HashMap;

abstract class Tool {
	private int level;

	
	
	void moreBusy() {
		level++;
	}

	void lessBusy() {
		assert level != 0;
		level--;
	}

	boolean isFree() {
		return level == 0;
	}

	HashMap<Integer, Tool> nest = new HashMap<Integer, Tool>();

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

	void presentation() {}
	
	void run() {
	};
}
