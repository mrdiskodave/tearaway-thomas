package com.nney.tt;

public abstract class Mode {
	abstract public String successMessage();

	public String failMessage() {
		return null;
	}

	public boolean hasExit() {
		return true;
	}

	public boolean delayedSuccess() {
		return false;
	}

	public boolean pauseInOutro() {
		return false;
	}

	abstract public void onTimeOut();

	abstract public String introText();
}
