package com.nney.tt.mapper;

import com.nney.tt.geom.Box;

public class ButtonRecord {
	public final Prop prop;
	public final int buttonNumber;
	public final Box collisionBox;

	public ButtonRecord(Prop prop, int buttonNumber, Box collisionBox) {
		this.prop = prop;
		this.buttonNumber = buttonNumber;
		this.collisionBox = collisionBox;
	}

	@Override
	public String toString() {
		return collisionBox.toString();
	}
}
