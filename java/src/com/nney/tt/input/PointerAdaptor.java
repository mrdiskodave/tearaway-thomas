package com.nney.tt.input;

public class PointerAdaptor implements Pointer {
	private final Pointer target;

	@Override
	public void set(int x, int y) {
		target.set(x, y);
	}

	public PointerAdaptor(Pointer target) {
		this.target = target;
	}

	@Override
	public int getX() {
		return target.getX();
	}

	@Override
	public int getY() {
		return target.getY();
	}

	@Override
	public boolean isDown(int key) {
		return target.isDown(key);
	}

	@Override
	public KeyEvent nextEvent() {
		return target.nextEvent();
	}
}
