package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BatGCImpl implements BatGC {
	private final Coord scr;
	private final MapperGC mgc;

	BatGCImpl(Coord scr, MapperGC mgc) {
		this.scr = scr;
		this.mgc = mgc;
	}

	public void drawBat(Coord c) {
		Box b = boxForBat(c);
		int x = b.left - scr.x;
		int y = b.top - scr.y;
		int w = b.width();
		int h = b.height();
		mgc.fillRectangle(x, y, w, h, 0xffffff00);
	}
	
	public static Box boxForBat(Coord c) {
		return Box.around(c, 4, 4);
	}

	@Override
	public void drawBox(Box box) {
		int x = box.left;
		int y = box.top;
		x -= scr.x;
		y -= scr.y;
		mgc.drawTransBox(x, y, box.width(), box.height(), 0xff000000, 0x60000000);
	}
}
