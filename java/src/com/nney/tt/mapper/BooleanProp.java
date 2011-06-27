package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;


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

	private void write(boolean n) {
		getFieldAccessor().put(n);
	}
	@Override
	String[] getButtons() {
		return new String[] { "change" };
	}

	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		System.out.println("Boolean click!");
		assert what == 0;
		write(!read());
	}


	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(DataItem d) {
		write(d.requireBoolean());
	}
}
