package com.nney.datanode;

public class NullNode extends NodeImpl {

	public @Override
	boolean isNull() {
		return true;
	}

	@Override
	public void save(DataDestination d) {
		d.writeNull();
	}
}
