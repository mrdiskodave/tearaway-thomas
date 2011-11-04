package com.nney.json;

public class ArrayBuilder implements Builder {
	private final JsonArray target;

	ArrayBuilder(JsonArray target) {
		this.target = target;
	}

	@Override
	public void take(JsonValue v) {
		target.add(v);
	}

	@Override
	public JsonValue value() {
		return target;
	}
}
