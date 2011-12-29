package com.nney.tt.input;

public interface Pointer extends HasKeys {
	public static final int KEY_POINTER = 256;
	public static final int KEY_LEFT = KEY_POINTER + 1;
	public static final int KEY_RIGHT = KEY_POINTER + 2;
	public static final int KEY_MIDDLE = KEY_POINTER + 3;
	public static final int KEY_UP = KEY_POINTER + 4;
	public static final int KEY_DOWN = KEY_POINTER + 5;

	int getX();

	int getY();

	void set(int x, int y);
}
