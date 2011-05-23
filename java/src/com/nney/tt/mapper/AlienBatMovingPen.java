package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienBatMovingPen extends Pen {
	private VisualAction selectedBat;
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
				Coord q = bat.where.copy();
				q.add(nudge);
				bat.action.takeAction(q);
			}
		}
	}

	@Override
	boolean down(Coord c) {
		BatRecord bat = srv.findBat(c);
		if (bat != null) {
			selectedBat = bat.action;
			srv.startAlienEdit();
			c.sub(bat.where);
			batGrip = c;
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
			c.sub(batGrip);
			selectedBat.takeAction(c);
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
