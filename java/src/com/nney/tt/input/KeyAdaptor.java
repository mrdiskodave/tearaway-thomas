package com.nney.tt.input;

public abstract class KeyAdaptor implements HasKeys {
	private int justPressed;
	private int whereAreWe;
	protected final HasKeys target;
	
	public KeyAdaptor(HasKeys target) {
		this.target = target;
	}

	@Override
	public int justPressed() {
		// if our target is ahead of us ..
		int whereIsOurTarget = target.periodNumber();
		if (whereIsOurTarget>whereAreWe) {
			whereAreWe = whereIsOurTarget;
			// .. we need to update
			justPressed = getNext();
		}
		return justPressed;
	}

	abstract protected int getNext();

	@Override
	public int periodNumber() {
		return target.periodNumber();
	}
}
