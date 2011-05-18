package com.nney.tt.mapper;

import com.nney.tt.Const;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class EyeDropperPen extends Pen {
	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	void stroke(Coord c) {
		c.div(Const.BLOCK_SIZE);
		srv.setCurrentBlockFromMap(c);
		srv.showBlocks();
		srv.keyboardBlockChoiceAndShow();
	}

}
