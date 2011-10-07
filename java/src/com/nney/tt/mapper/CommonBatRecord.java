package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class CommonBatRecord implements BatRecord {
	final private Bat bat;

	public CommonBatRecord(Bat bat) {
		this.bat = bat;
	}

	@Override
	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(getPosition()).inside(c);
	}

	@Override
	public void setPosition(Coord pos) {
		bat.onMove(pos);
	}

	@Override
	public Coord getPosition() {
		return bat.where();
	}
}
