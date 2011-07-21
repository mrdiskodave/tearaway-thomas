package com.nney.tt.sounds;

public class Timer {
	private int value;
	private int reset;
	
	boolean isTime() {
		if (reset==0) {
			// never
			return false;
		}
		if (value==0) {
			value = reset -1;
			// now!
			return true;
		}
		value--;
		// not yet
		return false;
	}
	
	void every(int r) {
		reset = r;
		value = reset -1; 
	}

	public void everyAndNextTime(int r) {
		reset = r;
		value = 0;
	}

	public void nextTime() {
		value = 0;
	}
}
