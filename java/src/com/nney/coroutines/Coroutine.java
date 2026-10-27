package com.nney.coroutines;

import java.util.Objects;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;

/**
 * A coroutine: a piece of straight-line code that runs a little at a time.
 *
 * <p>
 * The caller (usually the game loop, once a frame) calls {@link #step()}. The
 * coroutine's body then runs until it calls {@link #pause()}, at which point
 * {@link #step()} returns. The next {@link #step()} carries on from just after
 * that {@link #pause()}, with all the body's local variables intact. Only one
 * side ever runs at a time, so no locking is needed between them.
 *
 * <pre>
 * Coroutine timeBonus = new Coroutine("timeBonus", co -&gt; {
 * 	co.pause(60); // wait a second and a bit
 * 	while (time &gt; 0) {
 * 		score += 10;
 * 		time--;
 * 		co.pause(4);
 * 	}
 * });
 *
 * while (timeBonus.step()) {
 * 	drawFrame();
 * }
 * </pre>
 *
 * <p>
 * Implementation: the body runs on a Java 21 <i>virtual thread</i>. The JDK
 * implements those with real continuations, so a pause/resume is a cheap
 * continuation yield inside the JVM rather than an operating system thread
 * switch. (The continuation class itself, jdk.internal.vm.Continuation, is not
 * public API, which is why we go through virtual threads.)
 *
 * <p>
 * Exceptions thrown by the body are rethrown from {@link #step()}. Calling
 * {@link #close()} on an unfinished coroutine cancels it: its current
 * {@link #pause()} throws {@link CoTerminated} so that its <code>finally</code>
 * blocks run.
 */
public class Coroutine implements AutoCloseable {
	/** The code a coroutine runs. */
	@FunctionalInterface
	public interface Body {
		void run(Coroutine co);
	}

	private enum Turn {
		CALLER, COROUTINE
	}

	private final String name;
	private final Body body;

	private final ReentrantLock lock = new ReentrantLock();
	private final Condition turnChanged = lock.newCondition();

	// all guarded by lock
	private Turn turn = Turn.CALLER;
	private Thread thread;
	private boolean finished;
	private boolean cancelled;
	private Throwable failure;

	/**
	 * Make a coroutine. Nothing runs until the first {@link #step()}.
	 */
	public Coroutine(String name, Body body) {
		this.name = Objects.requireNonNull(name);
		this.body = Objects.requireNonNull(body);
	}

	/**
	 * For subclasses that override {@link #run()} instead of passing a
	 * {@link Body}.
	 */
	protected Coroutine(String name) {
		this.name = Objects.requireNonNull(name);
		this.body = null;
	}

	/** Override this if you subclass rather than pass a {@link Body}. */
	protected void run() {
		throw new IllegalStateException("No body given for coroutine " + name);
	}

	// ---------------------------------------------------------------------------
	// the caller's side

	/**
	 * Run the coroutine until its next {@link #pause()} or until it finishes.
	 *
	 * @return <code>true</code> if it paused (there is more to do),
	 *         <code>false</code> if it has finished.
	 * @throws RuntimeException
	 *             (or Error) whatever the body threw.
	 */
	public boolean step() {
		lock.lock();
		try {
			if (finished) return false;
			if (thread == null) {
				thread = Thread.ofVirtual().name("coroutine-" + name).unstarted(this::threadMain);
				turn = Turn.COROUTINE;
				thread.start();
			}
			else {
				handTo(Turn.COROUTINE);
			}
			awaitTurn(Turn.CALLER, false);
			if (failure != null) {
				Throwable t = failure;
				failure = null;
				rethrow(t);
			}
			return !finished;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Keep stepping until it finishes. Mostly useful in tests.
	 */
	public void runToCompletion() {
		while (step()) {
			// keep going
		}
	}

	public boolean isFinished() {
		lock.lock();
		try {
			return finished;
		}
		finally {
			lock.unlock();
		}
	}

	/**
	 * Abandon the coroutine. If it is part way through, its pending
	 * {@link #pause()} throws {@link CoTerminated} so it can tidy up. Safe to
	 * call more than once, or after it has finished.
	 */
	@Override
	public void close() {
		lock.lock();
		try {
			if (finished) return;
			if (thread == null) {
				finished = true;
				return;
			}
			cancelled = true;
			// normally once round is enough; more if the body catches
			// CoTerminated and pauses again (every pause() throws it)
			while (!finished) {
				handTo(Turn.COROUTINE);
				awaitTurn(Turn.CALLER, false);
			}
			failure = null; // anything it threw while unwinding is moot
		}
		finally {
			lock.unlock();
		}
	}

	// ---------------------------------------------------------------------------
	// the coroutine's side

	/**
	 * Give control back to the caller of {@link #step()} and wait until we're
	 * stepped again. Only call this from inside the coroutine's body.
	 */
	public void pause() {
		if (Thread.currentThread() != thread) {
			throw new IllegalStateException("pause() called from outside coroutine " + name);
		}
		lock.lock();
		try {
			handTo(Turn.CALLER);
			awaitTurn(Turn.COROUTINE, true);
		}
		finally {
			lock.unlock();
		}
	}

	/** {@link #pause()} n times, e.g. to wait n frames. */
	public void pause(int n) {
		while (--n >= 0) {
			pause();
		}
	}

	/** {@link #pause()} until the condition is true (checked before each pause). */
	public void waitUntil(BooleanSupplier condition) {
		while (!condition.getAsBoolean()) {
			pause();
		}
	}

	private void threadMain() {
		Throwable t = null;
		try {
			lock.lock();
			try {
				// step() already gave us the turn; just make sure we can't
				// start running before it's waiting for us
				awaitTurn(Turn.COROUTINE, true);
			}
			finally {
				lock.unlock();
			}
			if (body != null) body.run(this);
			else run();
		}
		catch (CoTerminated ex) {
			// cancelled by close(): a normal way to end
		}
		catch (Throwable ex) {
			t = ex;
		}
		lock.lock();
		try {
			finished = true;
			if (!cancelled) failure = t;
			handTo(Turn.CALLER);
		}
		finally {
			lock.unlock();
		}
	}

	// ---------------------------------------------------------------------------
	// plumbing (call with lock held)

	private void handTo(Turn t) {
		turn = t;
		turnChanged.signalAll();
	}

	private void awaitTurn(Turn t, boolean coroutineSide) {
		boolean interrupted = false;
		while (turn != t) {
			try {
				turnChanged.await();
			}
			catch (InterruptedException e) {
				interrupted = true;
			}
		}
		if (interrupted) Thread.currentThread().interrupt();
		if (coroutineSide && cancelled) throw new CoTerminated();
	}

	private static void rethrow(Throwable t) {
		if (t instanceof RuntimeException) throw (RuntimeException) t;
		if (t instanceof Error) throw (Error) t;
		throw new RuntimeException(t);
	}

	@Override
	public String toString() {
		return "Coroutine[" + name + "]";
	}
}
