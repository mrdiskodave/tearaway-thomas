package com.nney.tt;

public abstract class Coroutine extends Thread {
	public final CoHub hub;
	
	public final String name;

	Coroutine(CoHub hub, String name) {
		this.hub = hub;
		this.name = name;
	}
	
	public void pause() {
		hub.pauseFor(this);
	}

	@Override
	public void run() {
		go();
		System.out.println("Complete!");
	}

	public abstract void go();

}
