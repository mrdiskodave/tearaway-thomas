package com.nney.tt.mapper;

import java.util.HashMap;
import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;

abstract class Tool {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	private int level;
	private HashMap<Integer, Tool> nest = new HashMap<Integer, Tool>();

	protected Mapper srv;

	public Tool(Mapper srv) {
		this.srv = srv;
	}
	

	void drawBlockCursor() {
		Coord box = srv.computeMousePos(true);
		box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
		box.sub(srv.getScreenPosition());
		srv.getMGC().drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, srv.getMGC().process(COL_CURRENT_BLOCK));
	}

	protected void moreBusy() {
		level++;
		System.out.println("MORE BUSY" + level);
	}

	protected void lessBusy() {
		assert level != 0;
		level--;
		System.out.println("LESS BUSY" + level);
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
		if (isFree()) {
			for (Entry<Integer, Tool> e : nest.entrySet()) {
				if (srv.justPressed() == e.getKey()) {
					srv.pushTool(e.getKey(), e.getValue());
				}
			}
		}
	}

}
