package com.nney;

public class StopWatch {
	private long startTime;

	StopWatch() {
		startTime = System.nanoTime();
	}
	
	long readNano() {
		return System.nanoTime()-startTime; 
	}
	
	float readMsf() {
		return ((float) readNano()) / 1000000;
	}
}
