package com.nney;

// TODO: really this is a BobName
// TODO: really a Bob (amiga: blitter object) might be better named a Sprite
public class Frame {
	public final String name;
	public final int number;
	public int fx;

	public Frame(String name, int number, int fx) {
		this.fx = fx;
		assert name != null;
		this.name = name;
		this.number = number;
	}
	
	@Override
	public boolean equals(Object other) {
		 if (!(other instanceof Frame))
		      return false;
		 Frame us = (Frame) other;
		 return us.name.equals(name) && us.number==number && us.fx==fx;
	}
	
	@Override
	public int hashCode() {
		return name.hashCode()+number+fx*13;
	}
	
	@Override
	public String toString() {
		return String.format("Frame('%s', %d, %02x)", name, number, fx);
	}
}
