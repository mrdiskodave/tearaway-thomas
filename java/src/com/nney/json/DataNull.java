package com.nney.json;

public class DataNull extends DataItemImpl {

	public @Override
	boolean isNull() {
		return true;
	}

	@Override
	public void save(DataDestination d) {
		d.writeNull();
	}
}
