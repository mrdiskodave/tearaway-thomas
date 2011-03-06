package com.nney.utils;

import java.io.IOException;

public class OpenableTools {
	static public byte[] load(Openable openable) {
		try {
			return Pump.loadIntoByteArray(openable);
		}
		catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
}
