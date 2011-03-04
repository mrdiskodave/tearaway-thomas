package com.nney.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import com.nney.utils.mbr.MustBeClosedInputStream;

public class FileOpenable implements Openable {

	private final File f;

	public FileOpenable(File f) {
		this.f = f;
	}

	public FileOpenable(String f) {
		this.f = new File(f);
	}

	public InputStream open() throws IOException {
		return MustBeClosedInputStream.open(f);
	}
}
