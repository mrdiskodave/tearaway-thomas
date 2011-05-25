package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienBatMovingPen extends Pen {
	private BatRecord selectedBat;
	private Coord batGrip;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	void hover(Coord c) {
		BatRecord bat = srv.findBat(c);
		if (bat != null) {
			Coord nudge = srv.getNudge();
			if (nudge != null) {
				bat.press(nudge);
			}
		}
	}

	@Override
	boolean down(Coord c) {
		BatRecord bat = srv.findBat(c);
		if (bat != null) {
			selectedBat = bat;
			srv.startAlienEdit();
			batGrip = c.copy();
			return false;
		}
		else {
			noBat();
			return true;
		}
	}

	@Override
	void stroke(Coord c) {
		if (selectedBat != null) {
			selectedBat.press(c.sub2(batGrip));
			batGrip = c;
		}
	}

	@Override
	void up(Coord c) {
		if (selectedBat != null) {
			srv.endAlienEdit();
		}
		noBat();
	}

	private void noBat() {
		selectedBat = null;
		batGrip = null;
	}
}
