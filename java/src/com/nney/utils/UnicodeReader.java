package com.nney.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;

public class UnicodeReader extends Reader {
	private InputStreamReader in;

	UnicodeReader(InputStream inputStream, String defaultEncoding) throws IOException {
		UnicodeInputStream uis = new UnicodeInputStream(inputStream, defaultEncoding);
		String enc = uis.getEncoding();
		in = enc==null ? new InputStreamReader(uis) : new InputStreamReader(uis, enc);
	}

	// proxy ...
	
	@Override
	public void reset() throws IOException {
		in.reset();
	}

	@Override
	public long skip(long n) throws IOException {
		return in.skip(n);
	}

	@Override
	public String toString() {
		return in.toString();
	}

	@Override
	public void close() throws IOException {
		in.close();
	}

	@Override
	public int read() throws IOException {
		return in.read();
	}

	@Override
	public int read(char[] arg0, int arg1, int arg2) throws IOException {
		return in.read(arg0, arg1, arg2);
	}
}
