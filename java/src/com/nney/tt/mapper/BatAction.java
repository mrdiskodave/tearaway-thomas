package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatAction {
	private final Prop who;
	private final int what;

	public BatAction(Prop who, int what) {
		this.who = who;
		this.what = what;
	}

	public void takeAction(Coord c) {
		who.onBatMovement(what, c);
	}
}
