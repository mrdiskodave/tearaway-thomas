package com.nney.tt.input;

public interface Pointer {
	public static final int KEY_LEFT = 1;
	public static final int KEY_RIGHT = 2;
	public static final int KEY_MIDDLE = 4;

	int getX();
	int getY();
	int getDWheel();
	
	boolean isDown(int mask);
	boolean justPressed(int mask);
}
