package com.nney.json;

public class JsonBoolean extends JsonValue {
	private final boolean value;

	public JsonBoolean(boolean value) {
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
