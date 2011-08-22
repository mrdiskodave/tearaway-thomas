package com.nney.tt;

public class Strobe {
	private boolean poked;
	
	public synchronized void pause() {
		while (!poked) {
			try {
				wait();
			}
			catch (InterruptedException e) {
				// ignored
			}
		}
		poked = false;
	}

	public synchronized void poke() {
		poked = true;
	}
}
