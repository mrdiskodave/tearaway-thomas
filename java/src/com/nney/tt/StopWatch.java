package com.nney.tt;

public class StopWatch {
	private long startTime;

	public StopWatch() {
		startTime = System.nanoTime();
	}
	
	public long readNano() {
		return System.nanoTime()-startTime; 
	}
	
	public float readMsf() {
		return ((float) readNano()) / 1000000;
	}
}
