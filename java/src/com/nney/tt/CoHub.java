package com.nney.tt;

import java.util.concurrent.Semaphore;


public class CoHub {
	Semaphore waiting = new Semaphore(0, true);
	Semaphore permission = new Semaphore(0, true);
	
	public void pauseFor(Coroutine cr) {
		System.out.println("pause");

		
		// we finished the last bit
		waiting.release();

		// get permission for the next bit
		permission.acquireUninterruptibly();

		System.out.println("pause DONE");
	}

	private void next() {
		System.out.println("next ");
		
		
		// give it permission
		permission.release();
		// wait until it has finished
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
		
		try {
			System.out.println("zz");
			Thread.sleep(1000);
			System.out.println("zzzz");
		}
		catch (InterruptedException e) {
		}
		
		for (int r=0; r<10; r++) {
			System.out.println("---------------------------------------------------------------");
			System.out.println("real="+r);
			hub.next();
		}
	}
}
