package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;
import com.nney.tt.input.Pointer;

public class HandPen extends Pen {
	private Coord last;

	@Override
	int key() {
		return Pointer.KEY_LEFT;
	}
	
	@Override
	void down(Coord c) {
		last = c;
	}
	
	@Override
	void stroke(Coord c) {
		Coord delta = last.copy();
		delta.sub(c);
		System.out.println(last+"-"+c+"="+delta);
		last = c;
		srv.scroll(delta);
	}
	
	@Override
	boolean usesWorldCoords() {
		return false;
	}	
}
