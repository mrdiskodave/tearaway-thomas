package com.nney.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Reader;

import junit.framework.TestCase;

public class UnicodeReaderTest extends TestCase {
	public void testUtf8() throws Exception {
		assertWorks("\u00A9", "EFBBBFC2A9", null);
		assertWorks("\u2260", "EFBBBFE289A0", null);
		assertWorks("\u00A9", "EFBBBFC2A9", "UTF-8");
		assertWorks("\u2260", "EFBBBFE289A0", "UTF-8");
		assertWorks("\u00A9", "C2A9", "UTF-8");
	}

	public void testUtf16BE() throws Exception {
		assertWorks("\u00A9", "FEFF00A9", null);
		assertWorks("\u00A9", "FEFF00A9", "UTF-16");
		assertWorks("\u00A9", "00A9", "UTF-16");
	}

	public void testUtf16LE() throws Exception {
		assertWorks("\u00A9", "FFFEA900", null);
	}

	public void testDefault() throws Exception {
		assertWorks("hello", "68656c6c6f", "UTF-8");
	}

	private void assertWorks(String expectDecoded, String encoded, String defaultEncoding) throws IOException {
		byte[] b = HexServices.mustDecodeHex(encoded);
		try (Reader r = new UnicodeReader(new ByteArrayInputStream(b), defaultEncoding)) {
			StringBuilder s = new StringBuilder();
			for (;;) {
				int c = r.read();
				if (c < 0) {
					break;
				}
				s.append((char) c);
			}
			assertEquals(expectDecoded, s.toString());
		}
	}
}
