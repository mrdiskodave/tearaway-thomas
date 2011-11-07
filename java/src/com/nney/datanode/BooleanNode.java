package com.nney.datanode;

public class BooleanNode extends NodeImpl {
	private final boolean value;

	public BooleanNode(boolean value) {
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
