package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class CommonBatRecord implements BatRecord {
	final private Bat target;

	public CommonBatRecord(Bat bat) {
		this.target = bat;
	}

	@Override
	public boolean inside(Coord c) {
		return where2().inside(c);
	}

	@Override
	public void onMove(Coord pos) {
		target.onMove(pos);
	}

	@Override
	public Box where2() {
		return target.where2();
	}
}
