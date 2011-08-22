package com.nney.tt;

public class CoRow extends Thread {
	public final CoHub hub;
	
	public final String name;

	CoRow(CoHub hub, String name) {
		this.hub = hub;
		this.name = name;
	}
	
	synchronized public void pause() {
		hub.next();
		while (hub.current()!=Thread.currentThread()) {
			try {
				wait();
			}
			catch (InterruptedException e) {

			}
		}
	}

	public void pause(int frames) {
		for (int x=0; x<frames; x++) {
			pause();
		}
	}
}
