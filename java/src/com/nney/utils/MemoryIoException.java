package com.nney.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * A runtime exception meaning IO in memory (e.g. with
 * {@link ByteArrayOutputStream}) failed.
 * 
 * This can never happen but we still have an impossible {@link IOException} to
 * deal with. So we do is catch it and turn it into this.
 */
public class MemoryIoException extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public MemoryIoException() {
		super();
	}

	public MemoryIoException(String message, Throwable cause) {
		super(message, cause);
	}

	public MemoryIoException(String message) {
		super(message);
	}

	public MemoryIoException(Throwable cause) {
		super(cause);
	}
}
