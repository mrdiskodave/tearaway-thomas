package com.nney.utils.mbr;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;

public class MustBeClosedInputStream extends InputStream {
	private final InputStream target;

	private final MustBeReleased mbr = new MustBeReleased();

	public MustBeClosedInputStream(InputStream target) {
		this.target = target;
	}

	@Override
	public int available() throws IOException {
		return target.available();
	}

	@Override
	public void close() throws IOException {
		mbr.release();
		target.close();
	}

	@Override
	public boolean equals(Object obj) {
		return target.equals(obj);
	}

	@Override
	public int hashCode() {
		return target.hashCode();
	}

	@Override
	public void mark(int readlimit) {
		target.mark(readlimit);
	}

	@Override
	public boolean markSupported() {
		return target.markSupported();
	}

	@Override
	public int read() throws IOException {
		return target.read();
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return target.read(b, off, len);
	}

	@Override
	public int read(byte[] b) throws IOException {
		return target.read(b);
	}

	@Override
	public void reset() throws IOException {
		target.reset();
	}

	@Override
	public long skip(long n) throws IOException {
		return target.skip(n);
	}

	@Override
	public String toString() {
		return target.toString();
	}

	static public InputStream open(File file) throws FileNotFoundException {
		return new MustBeClosedInputStream(new FileInputStream(file));
	}

	public static InputStream open(String string) throws FileNotFoundException {
		return new MustBeClosedInputStream(new FileInputStream(string));
	}
}
