package com.nney.tt.mapper;


public class BooleanProp extends Prop {
	private final String textTrue;
	private final String textFalse;

	public BooleanProp(PropPack pp) {
		super(pp);
		String t = "YES";
		String f = "NO";
		if (pp.getAnn().xtraDef().equals("leftright")) {
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
		return (Boolean) getFieldAccessor().get();
	}

	@Override
	String[] getButtons() {
		return new String[] { "change" };
	}

	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		System.out.println("Boolean click!");
		assert what == 0;
		getFieldAccessor().put(!read());
	}
}
