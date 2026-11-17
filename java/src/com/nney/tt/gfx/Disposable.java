package com.nney.tt.gfx;

/**
 * An {@link AutoCloseable} whose {@link #close()} throws no checked exceptions,
 * so it can be used in try-with-resources without a catch.
 */
public interface Disposable extends AutoCloseable {
	/**
	 * Release any resources associated with this object.
	 */
	@Override
	void close();
}
