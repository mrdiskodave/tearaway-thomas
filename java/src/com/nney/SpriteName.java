package com.nney;

public class SpriteName {
	public final String name;
	public final int number;

	public SpriteName(String name, int number) {
		assert name != null;
		this.name = name;
		this.number = number;
	}
	
	@Override
	public boolean equals(Object other) {
		 if (!(other instanceof SpriteName))
		      return false;
		 SpriteName us = (SpriteName) other;
		 return us.name.equals(name) && us.number==number;
	}
	
	@Override
	public int hashCode() {
		return name.hashCode();
	}
	
	@Override
	public String toString() {
		return String.format("Frame('%s', %d, %02x)", name, number);
	}
}
