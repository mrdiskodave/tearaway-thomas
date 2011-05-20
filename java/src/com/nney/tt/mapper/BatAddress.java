package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatAddress {
	public final Prop who;
	public final int what;

	public BatAddress(Prop who, int what) {
		this.who = who;
		this.what = what;
	}

	public void moveTo(Coord c) {
		who.onBatMovement(what, c);
	}
}
