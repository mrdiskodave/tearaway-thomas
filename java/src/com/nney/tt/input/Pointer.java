package com.nney.tt.input;

public interface Pointer extends HasKeys {
	public static final int KEY_POINTER = 256;
	public static final int KEY_LEFT = KEY_POINTER + 1;
	public static final int KEY_RIGHT = KEY_POINTER + 2;
	public static final int KEY_MIDDLE = KEY_POINTER + 3;

	int getX();

	int getY();

	int getDWheel();
}
