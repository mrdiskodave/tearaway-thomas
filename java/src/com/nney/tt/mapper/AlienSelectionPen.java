package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienSelectionPen extends Pen {
	private BatAddress batAddress;
	private Coord delta;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		BatRecord bat = srv.grabBat(c);
		if (bat!=null) {
			batAddress = bat.address; 
			c.sub(bat.where);
			delta = c;
		}
		else {
			srv.selectNearestAlien(c);
		}
	}
	
	@Override
	void stroke(Coord c) {
		if (batAddress!=null) {
			c.sub(delta);
			batAddress.who.takeBatMovement(batAddress.what, c);
		}
	}
	
	@Override
	void always() {
		srv.showSelectedAlienProps();
	}
}
