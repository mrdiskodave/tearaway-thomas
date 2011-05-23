package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ButtonRecord implements Collidable {
	public final VisualAction action;
	private final Box collisionBox;

	public ButtonRecord(VisualAction action, Box collisionBox) {
		this.action = action;
		this.collisionBox = collisionBox;
	}

	@Override
	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}

	public String getUniqueName() {
		// no buttons entirely overlap so this'll do
		return collisionBox.toString();
	}
}
