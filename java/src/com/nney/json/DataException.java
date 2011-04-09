package com.nney.json;

/**
 * Triggered if the callers expectations about {@link DataItem} are violated.
 * This will only happen in the event that bad data has been supplied. This is
 * why this exception is unchecked.
 */
public class DataException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public DataException() {
		super();
	}

	public DataException(String message, Throwable cause) {
		super(message, cause);
	}

	public DataException(String message) {
		super(message);
	}

	public DataException(Throwable cause) {
		super(cause);
	}
}
