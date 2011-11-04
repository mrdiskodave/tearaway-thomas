package com.nney.json;

public abstract class JsonValue implements DataItem {
	@Override
	public DataItem requireElement(int position) throws DataException {
		throw new DataException("array expected");
	}

	@Override
	public DataItem requireField(String name) throws DataException {
		throw new DataException("object expected");
	}

	@Override
	public double requireDouble() throws DataException {
		throw new DataException("double expected");
	}

	@Override
	public int requireInt() throws DataException {
		try {
			return new Double(requireDouble()).intValue();
		}
		catch (DataException e) {
			throw new DataException("int expected");
		}
	}

	@Override
	public long requireLong() throws DataException {
		try {
			return new Double(requireDouble()).longValue();
		}
		catch (DataException e) {
			throw new DataException("long expected");
		}
	}

	@Override
	public boolean requireBoolean() throws DataException {
		throw new DataException("boolean expected");
	}

	@Override
	public String requireString() throws DataException {
		throw new DataException("string expected");
	}

	@Override
	public boolean isNull() {
		return false;
	}

	@Override
	public boolean fieldExists(String fieldName) throws DataException {
		throw new DataException("object expected");
	}

	@Override
	public DataItem[] requireList() throws DataException {
		throw new DataException("array expected");
	}
	
	public static JsonValue parse(String jsonInputString) throws JsonException {
		JsonValueBuilder builder = new JsonValueBuilder();
		JsonParser parser = new JsonParser(jsonInputString, builder);
		parser.parse();
		return builder.result();
	}
	
	public static JsonValue mustParse(String jsonString) {
		try {
			return parse(jsonString);
		}
		catch (JsonException e) {
			throw new RuntimeException(e);
		}
	}
}
