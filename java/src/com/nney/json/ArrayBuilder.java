package com.nney.json;

public class ArrayBuilder implements Builder {
	private final DataArray target;

	ArrayBuilder(DataArray target) {
		this.target = target;
	}

	@Override
	public void take(DataItemImpl v) {
		target.add(v);
	}

	@Override
	public DataItemImpl value() {
		return target;
	}
}
