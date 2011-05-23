package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatVisualAction implements VisualAction {
	private final Prop who;
	private final int what;

	public BatVisualAction(Prop who, int what) {
		this.who = who;
		this.what = what;
	}

	@Override
	public void takeAction(Coord c) {
		who.onBatMovement(what, c);
	}
}
