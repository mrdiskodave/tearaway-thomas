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
	public boolean testButton(int mask) {
		return target.testButton(mask);
	}

	@Override
	public boolean testButtonJustPressed(int mask) {
		return target.testButtonJustPressed(mask);
	}
}
