package com.nney.tt;

public abstract class Coroutine extends Thread {
	public final CoHub hub;
	
	public final String name;

	Coroutine(CoHub hub, String name) {
		this.hub = hub;
		this.name = name;
	}
	
	public void pause() {
		hub.stop(this);
		hub.start(this);
	}

	@Override
	public void run() {
		hub.start(this);
		go();
		hub.stop(this);
		
		for (;;) pause();
	}

	public abstract void go();

}
