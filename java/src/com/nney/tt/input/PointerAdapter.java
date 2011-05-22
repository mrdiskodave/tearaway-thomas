package com.nney.tt.input;

public class PointerAdapter implements Pointer {
	private final Pointer target;

	public PointerAdapter(Pointer target) {
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
	public int getDWheel() {
		return target.getDWheel();
	}

	@Override
	public boolean isDown(int mask) {
		return target.isDown(mask);
	}

	@Override
	public int justPressed() {
		return target.justPressed();
	}
}
