package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienSelectionPen extends Pen {

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		srv.selectNearestAlien(c);
	}
	
	@Override
	void always() {
		srv.showSelectedAlienProps();
	}
}
