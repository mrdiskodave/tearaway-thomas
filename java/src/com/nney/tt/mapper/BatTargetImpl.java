package com.nney.tt.mapper;

import java.util.List;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BatTargetImpl implements BatTarget {
	private final Coord scr;
	private final MapperGC mgc;
	private final List<BatRecord> target;
	private final Prop sender;
	private int number;

	BatTargetImpl(Coord scr, Prop sender, MapperGC mgc, List<BatRecord> target) {
		this.scr = scr;
		this.sender = sender;
		this.mgc = mgc;
		this.target = target;
	}

	public Coord firstBatPosition() {
		return target.get(0).where;
	}

	@Override
	public void drawBat(Coord c) {
		int x = c.x - scr.x;
		int y = c.y - scr.y;
		int i = 4;
		int w = i * 2 + 1;
		mgc.fillRectangle(x - i, y - i, w, w, 0xffffff00);
		Box batBox = Box.around(c, i, i);
		target.add(new BatRecord(new BatAddress(sender, number++), batBox, c));
		assert batBox.width() == w;
		assert batBox.height() == w;
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
