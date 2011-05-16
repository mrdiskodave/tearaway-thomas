package com.nney.tt.input;

public class PartialPointerImpl implements Pointer {
	private int currentPosition;
	private int lastPosition;
	private int x;
	private int y;
	private int w;

	protected void setNext(int x0, int y0, int w0, int b0) {
		lastPosition = currentPosition;
		currentPosition = b0;
		x = x0;
		y = y0;
		w = w0;
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
	public boolean isDown(int mask) {
		assert mask >= KEY_POINTER;
		mask -= KEY_POINTER;
		return (currentPosition&mask)!=0;
	}

	@Override
	public boolean justPressed(int mask) {
		int pressed = (~lastPosition)&currentPosition;
		return (pressed&mask)!=0;
	}

}
