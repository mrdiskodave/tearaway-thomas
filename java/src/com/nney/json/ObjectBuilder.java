package com.nney.json;

public class ObjectBuilder implements Builder {
	private String key;
	private final DataObject target;

	ObjectBuilder(DataObject target) {
		this.target = target;
	}

	@Override
	public void take(DataItem v) {
		if (key == null) {
			key = v.requireString();
		}
		else {
			target.put(key, v);
			key = null;
		}
	}
	
	@Override
	public DataItemImpl value() {
		return target;
	}
}
