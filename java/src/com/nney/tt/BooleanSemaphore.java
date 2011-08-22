package com.nney.tt;

public class BooleanSemaphore {
	private boolean destroyed;
	private boolean available;

	synchronized void acquireUninterruptibly() {
		for (;;) {
			if (destroyed) return;
			if (available) break;
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
		available = false;
	}
	
	synchronized void release() {
		if (destroyed) return;
		if (available) throw new IllegalStateException("You can only release it if you have it");
		available = true;
		notify();
	}

	synchronized void destroy() {
		destroyed = true;
		notify();
	}
	
	synchronized boolean destroyed() {
		return destroyed;
	}
}
