package com.nney.tt.mapper;

import java.awt.RenderingHints.Key;

import com.nney.tt.Const;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;
import com.nney.tt.map.GameMap;

public class RectangleTool extends Tool {
	public RectangleTool(Mapper srv) {
		super(srv);
	}

	private Box rectangle = Box.fromTopLeftAndSize(0, 0, GameMap.MAP_WIDTH, GameMap.MAP_HEIGHT);

	@Override
	String name() {
		return "box";
	}
	
	@Override
	void run() {
		checkPushTool();
		
		Coord c = srv.computeMousePos(true);
		c.div(Const.BLOCK_SIZE);
		if (srv.isDown(Keyboard.KEY_UP)) {
			rectangle.top = c.y;
		}
		if (srv.isDown(Keyboard.KEY_DOWN)) {
			rectangle.bottom = c.y;
		}
		if (srv.isDown(Keyboard.KEY_LEFT)) {
			rectangle.left = c.x;
		}
		if (srv.isDown(Keyboard.KEY_RIGHT)) {
			rectangle.right = c.x;
		}
		rectangle.validate();
		
		int k = srv.justPressed();
		if (k>=Keyboard.KEY_F1 && k<=Keyboard.KEY_F12) {
			int slotNumber = k-Keyboard.KEY_F1;
			srv.copyRect(slotNumber, rectangle);
		}
		
		Box t = rectangle.copy();
//		System.out.println("BigBox:"+t);
//		t.mul(Const.BLOCK_SIZE);
//		t.sub(getScreenPosition());
		Coord z = new Coord(t.left*Const.BLOCK_SIZE, t.top*Const.BLOCK_SIZE);
		z.sub(srv.getScreenPosition());
		int w = t.width()*Const.BLOCK_SIZE;
		int h = t.height()*Const.BLOCK_SIZE;
		srv.getMGC().drawTransBox(z.x, z.y, w, h, srv.getMGC().process(0xff00ff00), 0x60000000);
	}
}
