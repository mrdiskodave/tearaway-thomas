package com.nney.tt;

public abstract class CurtainImpl implements Curtain {
	protected int currentValue;
	protected int targetValue;
	private int targetState;

	@Override
	public void current(int state) {
		currentValue = stateToValue(state);
	}

	protected abstract int stateToValue(int state);

	@Override
	public void target(int state) {
		targetValue = stateToValue(state);
		targetState = state;
	}

	@Override
	public int target() {
		return targetState;
	}
	
	@Override
	public boolean isDone() {
		return currentValue==targetValue;
	}

}
