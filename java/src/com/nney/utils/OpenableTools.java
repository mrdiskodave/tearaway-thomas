package com.nney.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class OpenableTools {
	static public byte[] mustLoad(Openable openable) {
		try {
			return load(openable);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	public static byte[] load(Openable openable) throws IOException {
		InputStream in = openable.open();
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			new Pump(in, out).processToEof();
			return out.toByteArray();
		}
		finally {
			in.close();
		}
	}
}
