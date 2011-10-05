package com.nney.tt.input;

import com.nney.utils.Math2;

public class PartialPointerImpl implements Pointer {
	private int currentPosition;
	private int lastPosition;
	private int x;
	private int y;
	private int w;
	private int period;

	protected void setNext(int x0, int y0, int w0, int b0) {
		lastPosition = currentPosition;
		currentPosition = b0;
		x = x0;
		y = y0;
		w = w0;
		period++;
	}

	@Override
	public int getX() {
		return x;
	}

	@Override
	public int getY() {
		return y;
	}

	@Override
	public int getDWheel() {
		return w;
	}

	@Override
	public boolean isDown(int key) {
		if (key==Pointer.KEY_LEFT) return Math2.bitTest(currentPosition, 0);
		if (key==Pointer.KEY_RIGHT) return Math2.bitTest(currentPosition, 1);
		if (key==Pointer.KEY_MIDDLE) return Math2.bitTest(currentPosition, 2);
		return false;
	}

	@Override
	public int justPressed() {
		int pressed = (~lastPosition) & currentPosition;
		if (Math2.bitTest(pressed, 0)) return Pointer.KEY_LEFT;
		if (Math2.bitTest(pressed, 1)) return Pointer.KEY_RIGHT;
		if (Math2.bitTest(pressed, 2)) return Pointer.KEY_MIDDLE;
		return 0;
	}

	@Override
	public int periodNumber() {
		return period;
	}
}
