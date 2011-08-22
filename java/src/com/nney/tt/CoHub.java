package com.nney.tt;

import java.util.concurrent.Semaphore;


public class CoHub {
	Semaphore waiting = new Semaphore(0, true);
	Semaphore permission = new Semaphore(0, true);
	
	public void pauseFor(Coroutine cr) {
		System.out.println(Thread.currentThread());
		System.out.println("Pausing: "+cr.name);
		waiting.release();
		permission.acquireUninterruptibly();
	}

	private void next() {
		System.out.println("-------------------------- next frame");
		waiting.acquireUninterruptibly();
		permission.release();
	}

	public void add(Coroutine main) {
		main.setName(main.name);
		main.start();
	}
	
	public static void main(String[] args) {
		Thread.currentThread().setName("hub");
		System.out.println(Thread.currentThread());
		CoHub hub = new CoHub();
		Coroutine main = new Coroutine(hub, "test") {
			@Override
			public void go() {
				for (int x=0; x<5; x++) {
					System.out.println("x"+x);
					pause();
				}
			};
		};
		hub.add(main);
		for (int r=0; r<10; r++) {
			System.out.println("r"+r);
			hub.next();
		}
	}
}
