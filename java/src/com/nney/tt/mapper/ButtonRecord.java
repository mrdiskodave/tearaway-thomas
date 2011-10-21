package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.Button;

public class ButtonRecord implements Collidable {
	private final Button who;
	private final Box collisionBox;


	public ButtonRecord(Button who, Box collisionBox) {
		this.who = who;
		this.collisionBox = collisionBox;
	}

	@Override
	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}

	public void press() {
		who.press();
	}
}
