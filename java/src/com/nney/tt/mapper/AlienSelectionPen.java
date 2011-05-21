package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Keyboard;

public class AlienSelectionPen extends Pen {
	@Override
	int key() {
		return Keyboard.KEY_RETURN;
	}

	@Override
	void stroke(Coord c) {
		srv.selectNearestAlien(c);
	}

	@Override
	void always() {
		srv.showSelectedAlienProps();
	}
}
