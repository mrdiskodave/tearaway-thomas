package com.nney.datanode;

/**
 * Triggered if the callers expectations about {@link Node} are violated.
 * This will only happen in the event that bad data has been supplied. That is
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
