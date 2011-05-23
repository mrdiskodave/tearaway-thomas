package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

class ButtonVisualAction implements VisualAction {
	private final int bb;
	private final Prop p;
	private final ButtonPressServices bps;

	public ButtonVisualAction(ButtonPressServices bps, int bb, Prop p) {
		this.bps = bps;
		this.bb = bb;
		this.p = p;
	}

	@Override
	public void takeAction(Coord here) {
		p.onButtonPress(bb, bps);
	}
}
