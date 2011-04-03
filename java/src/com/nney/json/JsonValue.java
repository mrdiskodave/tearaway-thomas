package com.nney.json;

import java.io.File;
import java.io.IOException;

import com.nney.utils.FileOpenable;

public abstract class JsonValue implements DataItem {
	abstract public void writeJson(DataWriter writer) throws JsonException;

	public DataItem requireElement(int position) throws DataException {
		throw new DataException("array expected");
	}

	public DataItem requireField(String name) throws DataException {
		throw new DataException("object expected");
	}

	public double requireDouble() throws DataException {
		throw new DataException("double expected");
	}

	public int requireInt() throws DataException {
		try {
			return new Double(requireDouble()).intValue();
		}
		catch (DataException e) {
			throw new DataException("int expected");
		}
	}

	public long requireLong() throws DataException {
		try {
			return new Double(requireDouble()).longValue();
		}
		catch (DataException e) {
			throw new DataException("long expected");
		}
	}

	public boolean requireBoolean() throws DataException {
		throw new DataException("boolean expected");
	}

	public String requireString() throws DataException {
		throw new DataException("string expected");
	}

	public boolean isNull() {
		return false;
	}

	public boolean fieldExists(String fieldName) throws DataException {
		throw new DataException("object expected");
	}

	public DataItem[] requireList() throws DataException {
		throw new DataException("array expected");
	}

	public static JsonValue parse(String jsonString) throws JsonException {
		JsonInput jsonInput = new JsonInput(jsonString);
		JsonValue answer = jsonInput.nextValue();
		jsonInput.skipWhiteAndComments();
		if (!jsonInput.eof()) {
			throw jsonInput.syntaxError("Expected end of file");
		}
		return answer;
	}
}
