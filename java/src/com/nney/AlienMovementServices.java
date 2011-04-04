package com.nney;

public interface AlienMovementServices {

	int randomness(int n);

	/**
	 * Interact with the ground.
	 * 
	 * @param where
	 *            Where we're at.
	 * @param fallMax
	 *            The called-defined limit on falling (in pixels).
	 * @return Are we falling? <code>true</code> meaning "yes" (we fell for
	 *         fallMax and didn't it anything) or <code>false</code> meaning
	 *         "no" we aren't falling we are resting exactly one pixel above the
	 *         ground.
	 */
	boolean fallOrRaise(Coord where, int fallMax);

	boolean testKey(int key);
	
	/**
	 * What is there?
	 * @param where The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 * text string used in the configuration of a {@link BlockSpecifications} object.
	 */
	String getBlockSpecification(Coord where);
}