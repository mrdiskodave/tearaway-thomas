package com.nney.json;

public class JsonNull extends JsonValue {

	public @Override
	boolean isNull() {
		return true;
	}

	@Override
	public void writeJson(DataWriter writer) throws JsonException {
		writer.writeNull();
	}
}
