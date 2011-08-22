package com.nney.tt;

import java.util.concurrent.Semaphore;


public class CoHub {
	final Semaphore waiting = new Semaphore(0, true);
	final Semaphore permission = new Semaphore(0, true);


	void start(Coroutine coroutine) {
		// get permission for the next bit
		permission.acquireUninterruptibly();
	}

	void stop(Coroutine coroutine) {
		// we finished the last bit
		waiting.release();
	}

	private void next() {
		System.out.println("next");
		
		// give it permission for the next bit
		permission.release();
		// wait until it has finished the last bit
		waiting.acquireUninterruptibly();
		
		System.out.println("next DONE");
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
					System.out.println("co="+x);
					pause();
				}
			};
		};
		hub.add(main);
		
		for (int r=0; r<10; r++) {
			System.out.println("---------------------------------------------------------------");
			System.out.println("real="+r);
			hub.next();
		}
	}

	
}
