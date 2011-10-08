package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class CommonBatRecord implements BatRecord {
	final private Bat target;

	public CommonBatRecord(Bat bat) {
		this.target = bat;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(where()).inside(c);
	}

	@Override
	public void onMove(Coord pos) {
		target.onMove(pos);
	}

	@Override
	public Coord where() {
		return target.where();
	}
}
