package com.nney.json;

public class JsonException extends Exception {
	private static final long serialVersionUID = 1L;

	public JsonException() {
		super();
	}

	public JsonException(String message, Throwable cause) {
		super(message, cause);
	}

	public JsonException(String message) {
		super(message);
	}

	public JsonException(Throwable cause) {
		super(cause);
	}
}
