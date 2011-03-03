package com.nney.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Pump {
	private final InputStream in;

	private final OutputStream out;

	public Pump(InputStream in, OutputStream out) {
		this.in = in;
		this.out = out;
	}

	public long processToEof() throws IOException {
		return processBytes(Long.MAX_VALUE);
	}

	public long processBytes(long length) throws IOException {
		long done = 0;
		byte[] buffer = new byte[4096];
		while (length!=0) {
			int attempt = buffer.length;
			if (attempt>length) {
				attempt = (int) length;
			}
			int got = in.read(buffer, 0, attempt);
			if (got < 0) {
				break;
			}
			out.write(buffer, 0, got);
			done += got;
			length -= got;
		}
		return done;
	}
}