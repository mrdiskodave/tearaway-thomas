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
		srv.getHoverStatus().move(buttonRecordToString(srv.searchForButton(c)));
	}
	
	@Override
	void stroke(Coord c) {
		hover(c);
	}
	
	@Override
	boolean down(Coord c) {
		ButtonRecord br = srv.searchForButton(c);
		srv.getHoverStatus().down(buttonRecordToString(br));
		return br==null;
	}

	@Override
	void up(Coord c) {
		ButtonRecord selected = srv.searchForButton(c);
		if (srv.getHoverStatus().up(buttonRecordToString(selected))) {
			srv.startAlienEdit();
			selected.prop.onButtonPress(selected.buttonNumber, srv);
			srv.endAlienEdit();
		}
	}

	@Override
	boolean usesWorldCoords() {
		return false;
	}

	private String buttonRecordToString(ButtonRecord br) {
		if (br==null) return "";
		return br.getUniqueName();
	}
}
