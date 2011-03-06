package com.nney;

public class Frame {
	public final String name;
	public final int number;

	public Frame(String name, int number) {
		assert name != null;
		this.name = name;
		this.number = number;
	}
	
	@Override
	public boolean equals(Object other) {
		 if (!(other instanceof Frame))
		      return false;
		 Frame us = (Frame) other;
		 return us.name.equals(name) && us.number==number;
	}
	
	@Override
	public int hashCode() {
		return name.hashCode()+number;
	}
	
	@Override
	public String toString() {
		return String.format("Frame('%s', %d)", name, number);
	}
}
