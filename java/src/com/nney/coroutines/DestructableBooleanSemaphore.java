package com.nney.coroutines;

public class DestructableBooleanSemaphore {
	enum State {
		BOOKED,
		AVAILABLE,
		DESTROYED
	};
	private State state = State.BOOKED;

	synchronized void acquireUninterruptibly() {
		for (;;) {
			if (state==State.DESTROYED) throw new CoTerminated();
			if (state==State.AVAILABLE) break;
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
		state = State.BOOKED;
	}
	
	synchronized void release() {
		if (state==State.DESTROYED) throw new CoTerminated();
		if (state!=State.BOOKED) throw new IllegalStateException("You can only release it if you have it");
		state = State.AVAILABLE;
		notify();
	}

	synchronized void destroy() {
		state = State.DESTROYED;
		notify();
	}
	
	synchronized boolean destroyed() {
		return state==State.DESTROYED;
	}
}
