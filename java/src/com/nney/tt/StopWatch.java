package com.nney.tt;

public class StopWatch {
	private long startTime;

	public StopWatch() {
		startTime = System.nanoTime();
	}

	public long readNanosecondsLong() {
		return System.nanoTime() - startTime;
	}

	public float readMillisecondsFloat() {
		return ((float) readNanosecondsLong()) / 1000000;
	}
}
