package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienSelectionPen extends Pen {
	private BatAddress selectedBat;
	private Coord batGrip;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		BatRecord bat = srv.searchForBat(c);
		if (bat!=null) {
			selectedBat = bat.address; 
			c.sub(bat.where);
			batGrip = c;
		}
		else {
			noBat();
			srv.selectNearestAlien(c);
		}
	}
	
	private void noBat() {
		selectedBat = null;
		batGrip = null;
	}

	@Override
	void stroke(Coord c) {
		if (selectedBat!=null) {
			c.sub(batGrip);
			selectedBat.who.takeBatMovement(selectedBat.what, c);
		}
	}
	
	@Override
	void up(Coord c) {
		noBat();
	}
	
	@Override
	void always() {
		srv.showSelectedAlienProps();
	}
}
