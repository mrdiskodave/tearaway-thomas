package com.nney.json;

public class JsonNull extends JsonValue {

	public @Override
	boolean isNull() {
		return true;
	}

	@Override
	public void save(DataDestination d) {
		d.writeNull();
	}
}
