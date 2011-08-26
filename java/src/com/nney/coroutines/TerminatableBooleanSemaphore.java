package com.nney.coroutines;

class TerminatableBooleanSemaphore {
	enum State {
		ACQUIRED,
		RELEASED,
		TERMINATED
	};
	private State state = State.ACQUIRED;

	synchronized void acquireUninterruptibly() {
		for (;;) {
			if (state==State.TERMINATED) throw new CoTerminated();
			if (state==State.RELEASED) break;
			try {
				wait();
			}
			catch (InterruptedException e) {
			}
		}
		state = State.ACQUIRED;
	}
	
	synchronized void release() {
		if (state==State.TERMINATED) throw new CoTerminated();
		if (state!=State.ACQUIRED) throw new IllegalStateException("You can only release it if you have it");
		state = State.RELEASED;
		notify();
	}

	synchronized void terminate() {
		state = State.TERMINATED;
		notify();
	}
}
