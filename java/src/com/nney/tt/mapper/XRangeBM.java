package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeBM extends VisualProp {
	private static final int BORDER = 10;
	private final XRange t;

	public XRangeBM(AlienProp p, XRange t) {
		super(p);
		this.t = t;
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
		// 0
		rt.drawBat(new Coord(t.getMiddle(),alien.y));
		// 1
		rt.drawBat(new Coord(t.left, alien.y));
		// 2
		rt.drawBat(new Coord(t.right, alien.y));
	}

	@Override
	void moveTo(int what, Coord where) {
		switch (what) {
		case 0:
			t.add(where.x - t.getMiddle());
			break;
		case 1:
			t.setLeft(where.x, BORDER);
			break;
		case 2:
			t.setRight(where.x, BORDER);
			break;
		default:
			assert false;
		}
	}
	
	@Override
	public String text() {
		return String.format("%d-%d", t.left, t.right);
	}
}
