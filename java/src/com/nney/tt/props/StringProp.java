package com.nney.tt.props;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;

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
	void load(Node d) {
		write(d.requireString());
	}
}
