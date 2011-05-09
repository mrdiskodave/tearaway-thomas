package com.nney.tt.input;

public class PartialJoystickImpl implements Joystick {
	private int currentPosition;
	private int lastPosition;

	protected void setNext(int n) {
		lastPosition = currentPosition;
		currentPosition = n;
	}
	
	@Override
	public boolean test(int mask) {
		return (currentPosition&mask)!=0;
	}

	@Override
	public boolean testJustPressed(int mask) {
		int pressed = (~lastPosition)&currentPosition;
		return (pressed&mask)!=0;
	}

}
