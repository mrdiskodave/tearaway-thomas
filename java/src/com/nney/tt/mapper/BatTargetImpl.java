package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BatTargetImpl implements BatTarget {
	private final Coord scr;
	private final MapperGC mgc;
	private final List<BatRecord> batList = new ArrayList<BatRecord>();
	private final Prop sender;
	private int number;
	private final Coord alien;

	BatTargetImpl(Coord alien, Coord scr, Prop sender, MapperGC mgc) {
		this.alien = alien;
		this.scr = scr;
		this.sender = sender;
		this.mgc = mgc;
	}

	public boolean hasBats() {
		return !batList.isEmpty();
	}
	
	public Coord firstBatPosition() {
		return batList.get(0).where;
	}
	
	public void collectBats(List<BatRecord> destination) {
		for (BatRecord r: batList) {
			destination.add(r);
		}
	}

	@Override
	public void drawBat(int x) {
		drawBat(new Coord(x, alien.y));
	}

	@Override
	public void drawBat(Coord c) {
		int x = c.x - scr.x;
		int y = c.y - scr.y;
		int i = 4;
		int w = i * 2 + 1;
		mgc.fillRectangle(x - i, y - i, w, w, 0xffffff00);
		Box batBox = Box.around(c, i, i);
		batList.add(new BatRecord(new BatAddress(sender, number++), batBox, c));
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
