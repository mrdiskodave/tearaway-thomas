package com.nney.datanode;

class ArrayBuilder implements Builder {
	private final ArrayNode target;

	public ArrayBuilder(ArrayNode target) {
		this.target = target;
	}

	@Override
	public void take(Node v) {
		target.add(v);
	}

	@Override
	public NodeImpl value() {
		return target;
	}
}
