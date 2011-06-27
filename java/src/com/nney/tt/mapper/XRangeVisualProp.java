package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp<XRange> {
	private static final int BORDER = 10;

	public XRangeVisualProp(PropPack pp) {
		super(pp);
	}

	@Override
	public Coord[] getBats() {
		XRange t = read();
		int apy = alienPos().y;
		return new Coord[] { location(), new Coord(t.left, apy), new Coord(t.right, apy) };
	}
	
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		XRange t = read();
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
	}

	@Override
	void onBatMovement(int what, Coord where) {
		XRange t = read();
		switch (what) {
		case 0:
			onBring(where);
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
		XRange t = read();
		return String.format("x%d w%d", t.left, t.width());
	}

	@Override
	void onBring(Coord c) {
		XRange t = read();
		int delta = c.x;
		delta -= t.middle();
		t.add(delta);
		validate();
	}

	@Override
	public void validate() {
		XRange t = read();
		t.resideInside(World.WHOLE_MAP_BOUNDS_IN_PIXELS.toXRange());
	}
	
	@Override
	public void moveBy(Coord delta) {
		XRange t = read();
		t.add(delta.x);
	}

	@Override
	Coord location() {
		XRange t = read();
		int apy = alienPos().y;
		return new Coord(t.middle(), apy);
	}

	@Override
	void save(DataDestination d) {
		XRange t = read();
		t.save(d);
	}
	
	@Override
	void load(DataItem d) {
		write(XRange.load(d));
	}	
}
