package com.nney.utils;

/**
 Original pseudocode   : Thomas Weidenfeller
 Implementation tweaked: Aki Nieminen

 http://www.unicode.org/unicode/faq/utf_bom.html
 BOMs:
 00 00 FE FF    = UTF-32, big-endian
 FF FE 00 00    = UTF-32, little-endian
 FE FF          = UTF-16, big-endian
 FF FE          = UTF-16, little-endian
 EF BB BF       = UTF-8

 Win2k Notepad:
 Unicode format = UTF-16LE
 ***/

import java.io.*;

/**
 * This InputStream will recognize unicode BOM marks and will skip bytes if
 * getEncoding() method is called before any of the read(...) methods.
 */
class UnicodeInputStream extends InputStream {
	PushbackInputStream internalIn;
	String defaultEnc;
	String encoding;

	private static final int BOM_SIZE = 4;

	UnicodeInputStream(InputStream in, String defaultEnc) throws IOException {
		internalIn = new PushbackInputStream(in, BOM_SIZE);
		this.defaultEnc = defaultEnc;
		init();
	}

	public String getDefaultEncoding() {
		return defaultEnc;
	}

	public String getEncoding() {
		return encoding;
	}

	/**
	 * Read-ahead four bytes and check for BOM marks. Extra bytes are unread
	 * back to the stream, only BOM bytes are skipped.
	 */
	protected void init() throws IOException {
		byte bom[] = new byte[BOM_SIZE];
		int n, unread;
		n = internalIn.read(bom, 0, bom.length);

		if ((bom[0] == (byte) 0xEF) && (bom[1] == (byte) 0xBB) && (bom[2] == (byte) 0xBF)) {
			encoding = "UTF-8";
			unread = n - 3;
		}
		else if ((bom[0] == (byte) 0xFE) && (bom[1] == (byte) 0xFF)) {
			encoding = "UTF-16BE";
			unread = n - 2;
		}
		else if ((bom[0] == (byte) 0xFF) && (bom[1] == (byte) 0xFE)) {
			encoding = "UTF-16LE";
			unread = n - 2;
		}
		else if ((bom[0] == (byte) 0x00) && (bom[1] == (byte) 0x00) && (bom[2] == (byte) 0xFE)
				&& (bom[3] == (byte) 0xFF)) {
			encoding = "UTF-32BE";
			unread = n - 4;
		}
		else if ((bom[0] == (byte) 0xFF) && (bom[1] == (byte) 0xFE) && (bom[2] == (byte) 0x00)
				&& (bom[3] == (byte) 0x00)) {
			encoding = "UTF-32LE";
			unread = n - 4;
		}
		else {
			// Unicode BOM mark not found, unread all bytes
			encoding = defaultEnc;
			unread = n;
		}

		if (unread > 0)
			internalIn.unread(bom, (n - unread), unread);
	}

	@Override
	public void close() throws IOException {
		internalIn.close();
	}

	@Override
	public int read() throws IOException {
		return internalIn.read();
	}

	@Override
	public int read(byte[] arg0, int arg1, int arg2) throws IOException {
		return internalIn.read(arg0, arg1, arg2);
	}
}
