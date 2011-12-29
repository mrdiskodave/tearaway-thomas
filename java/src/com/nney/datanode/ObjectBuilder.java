package com.nney.datanode;

class ObjectBuilder implements Builder {
	private String key;
	private final ObjectNode target;

	public ObjectBuilder(ObjectNode target) {
		this.target = target;
	}

	@Override
	public void take(Node v) {
		if (key == null) {
			key = v.requireString();
		}
		else {
			target.put(key, v);
			key = null;
		}
	}

	@Override
	public NodeImpl value() {
		return target;
	}
}
