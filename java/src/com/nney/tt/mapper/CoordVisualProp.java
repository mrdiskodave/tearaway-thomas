package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.geom.Coord;

public class CoordVisualProp extends VisualProp {
	private final Coord t;

	public CoordVisualProp(PropPack pp) {
		super(pp);
		this.t = (Coord) pp.access().get();
		assert t!=null;
	}

	@Override
	public Coord[] getBats() {
		return new Coord[] { location() };
	}

	@Override
	void onBatMovement(int what, Coord where) {
		assert what == 0;
		onBring(where);
	}
	

	@Override
	void onBring(Coord c) {
		t.x = c.x;
		t.y = c.y;
	}

	@Override
	public void moveBy(Coord delta) {
		t.add(delta);
	}

	@Override
	public String text() {
		return String.format("x%dy%d", t.x, t.y);
	}

	@Override
	Coord location() {
		return t.copy();
	}
	
	@Override
	void save(DataDestination d) {
		d.beginArray();
		d.write(t.x);
		d.write(t.y);
		d.end();
	}
	
	@Override
	void load(DataItem d) {
		t.x = d.requireElement(0).requireInt();
		t.y = d.requireElement(1).requireInt();
	}	
}
