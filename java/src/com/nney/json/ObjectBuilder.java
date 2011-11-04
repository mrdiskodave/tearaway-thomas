package com.nney.json;

public class ObjectBuilder implements Builder {
	private String key;
	private final JsonObject target;

	ObjectBuilder(JsonObject target) {
		this.target = target;
	}

	@Override
	public void take(JsonValue v) {
		if (key == null) {
			key = v.requireString();
		}
		else {
			target.put(key, v);
			key = null;
		}
	}
	
	@Override
	public JsonValue value() {
		return target;
	}
}
