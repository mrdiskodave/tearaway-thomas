package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ButtonRecord {
	public final ButtonAction buttonAction;
	public final Box collisionBox;

	public ButtonRecord(ButtonAction buttonAction, Box collisionBox) {
		this.buttonAction = buttonAction;
		this.collisionBox = collisionBox;
	}

	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}

	public String getUniqueName() {
		// no buttons entirely overlap so this'll do
		return collisionBox.toString();
	}
}
