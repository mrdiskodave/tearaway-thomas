package com.nney.coroutines;

public abstract class Coroutine extends Thread {
	public final CoHub hub;
	
	public final String name;

	Coroutine(CoHub hub, String name) {
		this.hub = hub;
		this.name = name;
	}
	
	public void pause() {
		hub.stop();
		hub.start();
	}

	@Override
	public void run() {
		hub.start();
		go();
		hub.finished();
	}

	public abstract void go();

}
