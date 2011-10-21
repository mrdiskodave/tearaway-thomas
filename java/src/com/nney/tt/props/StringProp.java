package com.nney.tt.props;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;

public class StringProp extends SpecificProp<String> {
	public StringProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return read();
	}
	
	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(DataItem d) {
		write(d.requireString());
	}
}
