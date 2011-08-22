package com.nney.tt;

public class CoHub {
	final BooleanSemaphore waiting = new BooleanSemaphore();
	final BooleanSemaphore permission = new BooleanSemaphore();
	private boolean finished;

	void start() {
		// get permission for the next bit
		permission.acquireUninterruptibly();
	}

	void stop() {
		// we finished the last bit
		waiting.release();
	}

	synchronized void finished() {
		finished = true;
	}
	
	synchronized public boolean isFinished() {
		return finished;
	}

	private void next() {
		// give it permission for the next bit
		permission.release();
		// wait until it has finished the last bit
		if (!isFinished()) waiting.acquireUninterruptibly();
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
			if (hub.isFinished()) {
				break;
			}
		}
		System.out.println("---------------------------------------------------------------");
	}

}
