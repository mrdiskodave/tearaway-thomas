package com.nney.tt.input;

import com.nney.utils.Math2;

public abstract class PartialPointerImpl extends PartialHasKeysImpl implements Pointer {
	private int currentPosition;
	private int x;
	private int y;

	protected void setNext(int x0, int y0, int w, int b0) {
		int lastPosition = currentPosition;
		currentPosition = b0;
		x = x0;
		y = y0;
		if (w > 0) queueEvent(Pointer.KEY_UP);
		if (w < 0) queueEvent(Pointer.KEY_DOWN);
		int pressed = currentPosition & ~lastPosition;
		if (Math2.bitTest(pressed, 0)) queueEvent(Pointer.KEY_LEFT);
		if (Math2.bitTest(pressed, 1)) queueEvent(Pointer.KEY_RIGHT);
		if (Math2.bitTest(pressed, 2)) queueEvent(Pointer.KEY_MIDDLE);
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
	public boolean isDown(int key) {
		if (key == Pointer.KEY_LEFT) return Math2.bitTest(currentPosition, 0);
		if (key == Pointer.KEY_RIGHT) return Math2.bitTest(currentPosition, 1);
		if (key == Pointer.KEY_MIDDLE) return Math2.bitTest(currentPosition, 2);
		return false;
	}
}
