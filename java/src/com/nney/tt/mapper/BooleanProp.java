package com.nney.tt.mapper;

import com.nney.tt.aliens.AlienProp;

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
	String[] createButtons() {
		return new String[] { "toggle" };
	}

	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		System.out.println("Boolean click!");
		assert what == 0;
		fa.put(!read());
	}
}
