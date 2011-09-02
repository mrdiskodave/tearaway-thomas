package com.nney.coroutines;

public abstract class Coroutine implements Runnable {
	private final TerminatableBooleanSemaphore waiting = new TerminatableBooleanSemaphore();
	private final TerminatableBooleanSemaphore permission = new TerminatableBooleanSemaphore();

	public Coroutine(String name) {
		new Thread(new Runnable() {
			@Override
			public void run() {
				try {
					start();
					Coroutine.this.run();
					terminate();
				}
				catch (CoTerminated ex) {
					// only happens if the user calls terminate() directly
				}
			}
		}, name).start();
	}

	protected void start() {
		// get permission for the next bit
		// System.out.println("Trying Start");
		permission.acquireUninterruptibly();
		// System.out.println("Done Start");
	}

	protected void stop() {
		// we finished the last bit
		waiting.release();
	}

	public void terminate() {
		permission.terminate();
		waiting.terminate();
	}

	public void step() {
		// System.out.println("Trying Step");
		// give it permission for the next bit
		permission.release();
		// wait until it has finished the last bit
		waiting.acquireUninterruptibly();
		// System.out.println("Done Step");
	}

	protected void pause() {
		stop();
		start();
	}
	
	protected void pause(int n) {
		while (--n>=0) {
			pause();
		}
	}
}
