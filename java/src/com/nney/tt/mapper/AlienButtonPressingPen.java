package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class AlienButtonPressingPen extends Pen {
	private ButtonRecord selected;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}

	@Override
	void down(Coord c) {
		ButtonRecord selectable = srv.searchForButton(c);
		if (selectable != null) {
			selected = selectable;
			selected.prop.down();
		}
	}

	@Override
	void up(Coord c) {
		if (selected != null) {
			// ahhhh :O
			// the ButtonRecords and BatRecords get remade every frame
			// so the question of "THE SAME BUTTON?" isn't obvious
			//
			// with BatRecords we really want this as the response to
			// dragging one bat on other bats isn't something we want to work out
			//
			// but with buttons?
			//
			// currently, with BOTH,
			// the Pens hang on to a given reference and,
			// though the UI still remakes it, the one the pen
			// hangs on to can be used to modify the property
			//
			if (selected.collisionBox.inside(c)) {
				srv.startAlienEdit();
				selected.prop.onButtonPress(selected.buttonNumber);
				srv.endAlienEdit();
			}
			selected.prop.up();
		}
		selected = null;
	}

	@Override
	boolean usesWorldCoords() {
		return false;
	}
}
