package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienButtonPressingPen extends Pen {
	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	void hover(Coord c) {
		srv.getHoverStatus().move(brn(c));
	}
	
	@Override
	void stroke(Coord c) {
		srv.getHoverStatus().move(brn(c));
	}
	
	@Override
	void down(Coord c) {
		srv.getHoverStatus().down(brn(c));
	}

	@Override
	void up(Coord c) {
		if (srv.getHoverStatus().up(brn(c))) {
			ButtonRecord selected = srv.searchForButton(c);
			srv.startAlienEdit();
			selected.prop.onButtonPress(selected.buttonNumber);
			srv.endAlienEdit();
		}
	}

	@Override
	boolean usesWorldCoords() {
		return false;
	}

	String brn(Coord c) {
		ButtonRecord br = srv.searchForButton(c);
		if (br==null) return "";
		if (!br.collisionBox.inside(c)) return "";		
		return br.prop.getUniqueName();
	}
}
