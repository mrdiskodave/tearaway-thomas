package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class ButtonRecord {
	public final Prop who;
	public final int what;
	public final Box collisionBox;

	public ButtonRecord(Prop who, int what, Box collisionBox) {
		this.who = who;
		this.what = what;
		this.collisionBox = collisionBox;
	}

	public String getUniqueName() {
		return who.getUniqueName()+"#"+what;
	}

	public void onButtonPress(ButtonPressServices srv) {
		who.onButtonPress(what, srv);
	}

	public boolean inside(Coord c) {
		return collisionBox.inside(c);
	}
}
