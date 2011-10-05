package com.nney.tt.input;

public abstract class SubKeys implements HasKeys {
	private int justPressed;
	private int period;
	private final HasKeys target;
	
	public SubKeys(HasKeys target) {
		this.target = target;
	}

	@Override
	public int justPressed() {
		// if our target is ahead of us ..
		int whereIsOurTarget = target.periodNumber();
		if (whereIsOurTarget>period) {
			period = whereIsOurTarget;
			// .. we need to update
			justPressed = getNext();
		}
		return justPressed;
	}

	abstract protected int getNext();

	@Override
	public int periodNumber() {
		return period;
	}
}
