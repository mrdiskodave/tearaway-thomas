package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Coord;

public class BooleanProp extends Prop {
	private final String textTrue;
	private final String textFalse;

	public BooleanProp(AlienProp aprop, FieldAccessor fa) {
		super(aprop, fa);
		String t = "YES";
		String f = "NO";
		if (aprop.xtraDef().equals("leftright")) {
			t = "LEFT";
			f = "RIGHT";
		}
		textTrue = t;
		textFalse = f;
	}

	@Override
	public String text() {
		return read() ? textTrue : textFalse;
	}

	private boolean read() {
		return (Boolean) fa.get();
	}

	@Override
	void createBats(Coord alien, BatTarget rt) {
		// do nothing because we are not a visual property
	}

	@Override
	void moveTo(int what, Coord where) {
		// do nothing because we are not a visual property
	}
}
