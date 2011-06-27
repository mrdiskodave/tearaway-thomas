package com.nney.tt.mapper;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;

public class IntegerProp extends SpecificProp<Integer> {
	public IntegerProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return Integer.toString(read());
	}
	
	@Override
	String[] getButtons() {
		return new String[] { "more", "less" };
	}

	@Override
	void onButtonPress(int what, ButtonPressServices bps) {
		if (what==0) {
			write(read()+1);
		}
		else {
			write(read()-1);
		}
	}
	
	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(DataItem d) {
		write(d.requireInt());
	}
}
