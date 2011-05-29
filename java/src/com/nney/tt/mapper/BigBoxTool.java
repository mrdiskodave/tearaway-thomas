package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;
import com.nney.tt.map.GameMap;

public class BigBoxTool extends Tool {
	public BigBoxTool(Mapper parent) {
		super(parent);
	}

	private Box bigBox = Box.fromTopLeftAndSize(0, 0, GameMap.MAP_WIDTH, GameMap.MAP_HEIGHT);

	@Override
	String name() {
		return "box";
	}
	
	@Override
	void run() {
		checkPushTool();

		Coord c = parent.computeMousePos(true);
		c.div(Const.BLOCK_SIZE);
		if (parent.isDown(Keyboard.KEY_UP)) {
			bigBox.top = c.y;
		}
		if (parent.isDown(Keyboard.KEY_DOWN)) {
			bigBox.bottom = c.y;
		}
		if (parent.isDown(Keyboard.KEY_LEFT)) {
			bigBox.left = c.x;
		}
		if (parent.isDown(Keyboard.KEY_RIGHT)) {
			bigBox.right = c.x;
		}
		bigBox.validate();
		
		Box t = bigBox.copy();
		System.out.println("BigBox:"+t);
//		t.mul(Const.BLOCK_SIZE);
//		t.sub(getScreenPosition());
		Coord z = new Coord(t.left*Const.BLOCK_SIZE, t.top*Const.BLOCK_SIZE);
		z.sub(parent.getScreenPosition());
		int w = t.width()*Const.BLOCK_SIZE;
		int h = t.height()*Const.BLOCK_SIZE;
		parent.getMGC().drawTransBox(z.x, z.y, w, h, parent.getMGC().process(0xff00ff00), 0x60000000);
	}
}
