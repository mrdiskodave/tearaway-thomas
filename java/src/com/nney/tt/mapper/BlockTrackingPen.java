package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;

public class BlockTrackingPen extends Pen {
	private Coord last;
	
	@Override
	int key() {
		return Keyboard.KEY_LCONTROL;
	}
	
	@Override
	void down(Coord c) {
		c.div(Const.BLOCK_SIZE);
		last = c;
	}
	
	@Override
	void stroke(Coord c) {
		c.div(Const.BLOCK_SIZE);
		Coord delta = c.copy();
		delta.sub(last);
		last = c;
		srv.changeCurrentBlock(delta.x, delta.y);
	}
}
