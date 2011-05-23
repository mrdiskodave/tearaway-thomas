package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ButtonRecord implements Collidable {
	private final int what;
	private final Prop who;
	private final ButtonPressServices bps;
	private final Box collisionBox;

	public ButtonRecord(int what, Prop who, ButtonPressServices bps, Box collisionBox) {
		this.what = what;
		this.who = who;
		this.bps = bps;
		this.collisionBox = collisionBox;
	}

	@Override
	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}

	public void press() {
		who.onButtonPress(what, bps);
	}

	public String getUniqueName() {
		// no buttons entirely overlap so this'll do
		return collisionBox.toString();
	}
	
}
