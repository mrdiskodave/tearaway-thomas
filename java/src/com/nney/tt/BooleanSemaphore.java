package com.nney.tt;

public class BooleanSemaphore {
	private boolean available;

	synchronized void acquireUninterruptibly() {
		while (!available) {
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
		available = false;
	}
	
	synchronized void release() {
		if (available) throw new IllegalStateException("You can only release it if you have it");
		available = true;
		notify();
	}
}
