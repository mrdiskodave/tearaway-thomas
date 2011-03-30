package com.nney.json;

public class JsonField {
	public final String name;
	public final JsonValue value;

	public JsonField(String name, JsonValue value) {
		this.name = name;
		this.value = value;
	}
}
