package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienSelectionPen extends Pen {
	@Override
	void presentation() {
		srv.showSelectedAlienProps();
	}

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	void stroke(Coord c) {
		srv.selectNearestAlien(c);
	}
}
