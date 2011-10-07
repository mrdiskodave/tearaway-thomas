package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BatGCImpl implements BatGC {
	private static final int SUPERBAT_SIZE = 10;
	private final Coord scr;
	private final MapperGC mgc;

	BatGCImpl(Coord scr, MapperGC mgc) {
		this.scr = scr;
		this.mgc = mgc;
	}

	public void drawBat(Coord c) {
		Box b = boxForBat(c).sub2(scr);
		mgc.fillRectangle(b.left, b.top, b.width(), b.height(), 0xffffff00);
	}
	
	public void drawSuperBat(Coord c) {
		c = c.sub2(scr);
		mgc.drawSight2(c.x, c.y, 25, mgc.process(0xff00ffff), SUPERBAT_SIZE, 0x40000000);
	}

	public static Box boxForBat(Coord c) {
		return Box.around(c, 4);
	}

	public static Box boxForSuperBat(Coord c) {
		return Box.around(c, SUPERBAT_SIZE);
	}

	@Override
	public void drawBox(Box box) {
		box = box.sub2(scr);
		mgc.drawTransBox(box.left, box.top, box.width(), box.height(), 0xff000000, 0x60000000);
	}
}
