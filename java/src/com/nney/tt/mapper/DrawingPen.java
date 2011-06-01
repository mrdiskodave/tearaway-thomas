package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class DrawingPen extends Pen {

	private EditDestination edit;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	boolean down(Coord c) {
		edit = srv.startBlockEdit();
		return false;
	}

	@Override
	void stroke(Coord c) {
		c.div(Const.BLOCK_SIZE);
		edit.setBlock(c, srv.getCurrentBlock());
	}

	@Override
	void up(Coord c) {
		srv.endBlockEdit();
	}

	@Override
	void otherActions() {
		srv.keyboardBlockChoice(false);
		srv.perhapsPaste();
	}
}
