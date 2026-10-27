package com.nney.coroutines;

/**
 * Thrown inside a coroutine's body, from {@link Coroutine#pause()}, when the
 * coroutine has been {@link Coroutine#close() closed}. Don't catch it: let it
 * unwind the body so <code>finally</code> blocks run.
 */
public class CoTerminated extends RuntimeException {
	private static final long serialVersionUID = 1L;

	public CoTerminated() {
		super(null, null, false, false);
	}
}
