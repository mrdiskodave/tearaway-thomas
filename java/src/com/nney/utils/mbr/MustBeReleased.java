package com.nney.utils.mbr;

public class MustBeReleased {
	private Throwable trace;

	private boolean hasBeenReleased;

	public MustBeReleased() {
		trace = new Throwable();
	}

	@Override
	public void finalize() {
		if (!hasBeenReleased) {
			throw new RuntimeException("Resource not released", trace);
		}
	}

	public void release() {
		hasBeenReleased = true;
	}
}
