package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienSelectionPen extends Pen {

	private BatAddress batAddress;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		batAddress = srv.grabBat(c);
		if (batAddress==null) {
			srv.selectNearestAlien(c);
		}
	}
	
	@Override
	void stroke(Coord c) {
		if (batAddress!=null) {
			batAddress.who.takeMovement(batAddress.what, c);
		}
	}
	
	@Override
	void always() {
		srv.showSelectedAlienProps();
	}
}
