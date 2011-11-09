package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.props.Button;

public class ButtonRecord implements Collidable {
	private final Button who;
	private final Box collisionBox;
	public final String label;
	public final Coord position;


	public ButtonRecord(Button who, Box collisionBox, String label, Coord position) {
		this.who = who;
		this.collisionBox = collisionBox;
		this.label = label;
		this.position = position;
	}

	@Override
	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}

	public void press() {
		who.press();
	}
}
