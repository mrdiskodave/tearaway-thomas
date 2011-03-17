package com.nney.utils;

import java.io.IOException;

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
		return Pump.loadIntoByteArray(openable);
	}
}
