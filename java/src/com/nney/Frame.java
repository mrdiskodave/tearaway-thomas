package com.nney;

public class Frame {
	public final String file;
	public final int number;

	public Frame(String file, int number) {
		assert file != null;
		this.file = file;
		this.number = number;
	}
	
	@Override
	public boolean equals(Object other) {
		 if (!(other instanceof Frame))
		      return false;
		 Frame us = (Frame) other;
		 return us.file.equals(file) && us.number==number;
	}
	
	@Override
	public int hashCode() {
		return file.hashCode()+number;
	}
	
	@Override
	public String toString() {
		return String.format("Frame('%s', %d)", file, number);
	}
}
