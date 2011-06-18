package com.nney.tt.mapper;

public class IntegerProp extends Prop {

	public IntegerProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return Integer.toString(read());
	}
	
	private int read() {
		return (Integer) getFieldAccessor().get();
	}
	
	@Override
	String[] getButtons() {
		return new String[] { "more", "less" };
	}

	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		if (what==0) {
			getFieldAccessor().put(read()+1);
		}
		else {
			getFieldAccessor().put(read()-1);
		}
	}
}
