package com.nney.utils.mbr;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class MustBeClosedOutputStream extends OutputStream {
	private final OutputStream target;

	private MustBeReleased mbr = new MustBeReleased();
	
	public MustBeClosedOutputStream(OutputStream target) {
		this.target = target;
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
	public void flush() throws IOException {
		target.flush();
	}

	@Override
	public int hashCode() {
		return target.hashCode();
	}

	@Override
	public String toString() {
		return target.toString();
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		target.write(b, off, len);
	}

	@Override
	public void write(byte[] b) throws IOException {
		target.write(b);
	}

	@Override
	public void write(int b) throws IOException {
		target.write(b);
	}

	
	public static OutputStream open(File file) throws FileNotFoundException {
		return new MustBeClosedOutputStream(new FileOutputStream(file));
	}

	public static OutputStream open(String string) throws FileNotFoundException {
		return new MustBeClosedOutputStream(new FileOutputStream(string));
	}
}
