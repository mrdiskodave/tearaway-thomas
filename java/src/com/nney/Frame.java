package com.nney;

public class Frame {
	public final String file;
	public final int number;

	public Frame(String file, int number) {
		assert file != null;
		this.file = file;
		this.number = number;
	}
}
