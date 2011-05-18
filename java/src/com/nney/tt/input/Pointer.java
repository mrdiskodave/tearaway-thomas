package com.nney.tt.input;

public interface Pointer {
	public static final int KEY_POINTER = 0x1000;
	public static final int KEY_LEFT = KEY_POINTER + 1;
	public static final int KEY_RIGHT = KEY_POINTER + 2;
	public static final int KEY_MIDDLE = KEY_POINTER + 4;

	int getX();

	int getY();

	int getDWheel();

	boolean isDown(int mask);

	boolean justPressed(int mask);
}
