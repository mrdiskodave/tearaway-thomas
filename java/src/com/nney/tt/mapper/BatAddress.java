package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatAddress {
	public final VisualProp who;
	public final int what;

	public BatAddress(VisualProp who, int what) {
		this.who = who;
		this.what = what;
	}
	
	public void moveTo(Coord c) {
		who.moveTo(what, c);
	}
}
