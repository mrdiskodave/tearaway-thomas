package com.nney.tt.input;

public interface Pointer {
	public static final int LEFT = 1;
	public static final int RIGHT = 2;
	public static final int MIDDLE = 4;

	int getX();
	int getY();
	int getDWheel();
	
	boolean testButton(int mask);
	boolean testButtonJustPressed(int mask);
}
