package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class DrawingPen extends Pen {

	private EditConsolidator edit;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		edit = srv.startEdit();
	}
	
	@Override
	void stroke(Coord c) {
		c.div(Const.BLOCK_SIZE);
		edit.setBlock(c, srv.getCurrentBlock());
	}
	
	@Override
	void up(Coord c) {
		srv.submitEdit(edit);
	}
	
	@Override
	void always() {
		srv.keyboardBlockChoiceAndShow();
	}
}
