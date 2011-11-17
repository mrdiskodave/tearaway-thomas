package com.nney.utils.mbr;

import java.io.InputStream;

/**
 * <p>
 * An object that requires that you call {@link #release()} before it is garbage
 * collected. If you do not it will generate an assert documenting its
 * construction position.
 * 
 * <p>
 * What problem is this trying to solve? Problem: some objects aren't
 * automatically garbage collected and must be manually released (e.g. an
 * {@link InputStream} needs a {@link InputStream#close()}). This is part of the
 * "contract" of working with such a class. We could say it has a
 * "must be released" contract. If the caller forgets to do the manual release
 * then they create a resource leak (e.g. a file handle leak). The system will
 * run out of the leaking resource and will break.
 * 
 * <p>
 * Any class we define that owns an object with a "must be released" contract
 * must, itself, impose a "must be released" contract upon its callers. This
 * means that this awkward contract propagates all over the place! OpenGL is a
 * good example of a package with many such contracts.
 * 
 * <p>
 * A partial solution is that you use {@link MustBeReleased} in all classes you
 * write that have a "must be released" contract. In your release method (
 * <code>close()</code> or <code>dispose()</code> or whatever) you do the things
 * that required you imposing that contract in the first place, e.g. releasing
 * some of your own fields, and, only then, call {@link #release()}. Then the
 * {@link MustBeReleased} object can be garbage collected without complaining.
 * Then, at the next full garbage collection, you are assured that your caller
 * has honoured the contract you imposed on them.<br>
 * (while hunting for leaks you can bring the next garbage collection earlier by
 * calling {@link System#gc()})
 * 
 * <p>
 * Using this is extra overhead but this area is such a can-of-worms that it is
 * often worth it. This class checks the assert mechanism and remains silent if
 * asserts are off.
 */
public class MustBeReleased {
	static boolean assertsEnabled;
	static {
		assertsEnabled = false;
		assert assertsEnabled = true; // Intentional side effect!!!
	}

	private Throwable trace;

	private boolean hasBeenReleased;

	public MustBeReleased() {
		trace = new Throwable();
	}

	@Override
	public void finalize() {
		// no point throwing from in here as it won't go anywhere
		if (assertsEnabled && !hasBeenReleased) {
			System.err.println("MustBeReleased without release()");
			trace.printStackTrace(System.err);
		}
	}

	public void release() {
		hasBeenReleased = true;
	}
}
