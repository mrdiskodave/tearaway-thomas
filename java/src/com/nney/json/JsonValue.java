package com.nney.json;

public class JsonValue {
	public static DataItem parse(String jsonInputString) throws JsonException {
		JsonValueBuilder builder = new JsonValueBuilder();
		JsonParser parser = new JsonParser(jsonInputString, builder);
		parser.parse();
		return builder.result();
	}
	
	public static DataItem mustParse(String jsonString) {
		try {
			return parse(jsonString);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}
}
