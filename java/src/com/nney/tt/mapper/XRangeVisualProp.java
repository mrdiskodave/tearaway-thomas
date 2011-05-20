package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final XRange t;

	public XRangeVisualProp(AlienProp p, FieldAccessor fa) {
		super(p, fa);
		this.t = (XRange) fa.get();
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
		// 0
		rt.drawBat(new Coord(t.middle(), alien.y));
		// 1
		rt.drawBat(new Coord(t.left, alien.y));
		// 2
		rt.drawBat(new Coord(t.right, alien.y));
	}

	@Override
	void onBatMovement(int what, Coord where) {
		switch (what) {
		case 0:
			t.add(where.x - t.middle());
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
		return String.format("x%d w%d", t.left, t.width());
	}
}
