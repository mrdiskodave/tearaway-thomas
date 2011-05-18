package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BoxVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final Box t;

	BoxVisualProp(AlienProp p, FieldAccessor fa) {
		super(p, fa);
		this.t = (Box) fa.get();
	}

	@Override
	public void createBats(Coord alien, BatTarget rt) {
		rt.drawBox(t);
		// 0
		rt.drawBat(t.middle());
		// 1
		rt.drawBat(t.topLeft());
		// 2
		rt.drawBat(t.bottomRight());
		// 3
		rt.drawBat(t.topRight());
		// 4
		rt.drawBat(t.bottomLeft());
	}

	@Override
	void moveTo(int what, Coord where) {
		switch (what) {
		case 0:
			where.sub(t.middle());
			t.add(where);
			break;
		case 1:
			t.setLeft(where.x, BORDER);
			t.setTop(where.y, BORDER);
			break;
		case 2:
			t.setRight(where.x, BORDER);
			t.setBottom(where.y, BORDER);
			break;
		case 3:
			t.setRight(where.x, BORDER);
			t.setTop(where.y, BORDER);
			break;
		case 4:
			t.setLeft(where.x, BORDER);
			t.setBottom(where.y, BORDER);
			break;
		default:
			assert false;
		}
	}

	@Override
	public String text() {
		return String.format("%dx%d,%dx%d", t.left, t.top, t.right, t.bottom);
	}
}
