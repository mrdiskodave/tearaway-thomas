package com.nney.tt.input;

public interface Joystick {
	public static final int DOWN = 1;
	public static final int RIGHT = 2;
	public static final int UP = 4;
	public static final int LEFT = 8;
	public static final int FIRE = 16;

	int get();
}
