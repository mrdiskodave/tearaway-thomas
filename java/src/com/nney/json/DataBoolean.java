package com.nney.json;

public class DataBoolean extends DataItemImpl {
	private final boolean value;

	public DataBoolean(boolean value) {
		this.value = value;
	}

	public @Override
	boolean requireBoolean() {
		return value;
	}

	@Override
	public void save(DataDestination d) {
		d.write(value);
	}
}
