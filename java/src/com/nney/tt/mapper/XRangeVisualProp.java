package com.nney.tt.mapper;

import com.nney.tt.World;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;

public class XRangeVisualProp extends VisualProp {
	private static final int BORDER = 10;
	private final XRange t;

	public XRangeVisualProp(PropPack pp) {
		super(pp);
		this.t = (XRange) pp.access().get();
		assert t!=null;
	}

	@Override
	public Coord[] getBats() {
		int apy = alienPos().y;
		return new Coord[] { location(), new Coord(t.left, apy), new Coord(t.right, apy) };
	}
	
	@Override
	public void drawAuxBatStuff(BatGC rt) {
		Box box = new Box(t.left, Integer.MIN_VALUE / 4, t.right, Integer.MAX_VALUE / 4);
		rt.drawBox(box);
	}

	@Override
	void onBatMovement(int what, Coord where) {
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
		return String.format("x%d w%d", t.left, t.width());
	}

	@Override
	void onBring(Coord c) {
		int delta = c.x;
		delta -= t.middle();
		t.add(delta);
		validate();
	}

	@Override
	public void validate() {
		t.resideInside(World.WHOLE_MAP_BOUNDS.toXRange());
	}
	
	@Override
	public void moveBy(Coord delta) {
		t.add(delta.x);
	}

	@Override
	Coord location() {
		int apy = alienPos().y;
		return new Coord(t.middle(), apy);
	}
	
}
