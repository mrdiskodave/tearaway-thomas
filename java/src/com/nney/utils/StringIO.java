package com.nney.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;

public class StringIO {
	public static String loadText(Openable o, String defaultEncoding) throws IOException {
		InputStream i = o.open();
		try {
			return loadText(i, defaultEncoding);
		}
		finally {
			i.close();
		}
	}

	public static String loadText(InputStream inputStream, String defaultEncoding) throws IOException {
		return loadText(new UnicodeReader(inputStream, defaultEncoding));
	}

	public static String loadText(Reader r) throws IOException {
		char[] c = new char[4096];
		StringBuffer ss = new StringBuffer();
		for (;;) {
			int got = r.read(c);
			if (got < 0) {
				break;
			}
			ss.append(c, 0, got);
		}
		return ss.toString();
	}

	
}
