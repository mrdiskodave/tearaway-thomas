package com.nney.tt;

import java.util.Random;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.map.BlockSpecifications;

public interface AlienMovementServices {

	/**
	 * Get some randomness.
	 * 
	 * @param n Exactly like the parameter given to {@link Random#nextInt(int)}.
	 * @return
	 */
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

	/**
	 * Is a key pressed.
	 * 
	 * @param key
	 *            The key the caller is asking about.
	 * @return <code>true</code> meaning "it is" or <code>false</code> meaning
	 *         "it is not".
	 */
	boolean testKey(int key);

	/**
	 * What is there?
	 * 
	 * @param where
	 *            The pixel location being queried.
	 * @return The kind of block that is there. e.g. "magic" or "ladder" or any
	 *         text string used in the configuration of a
	 *         {@link BlockSpecifications} object.
	 */
	String getBlockSpecification(Coord where);

	Coord getPlayerPosition();
	
	void playerBehind();
	
	boolean collideWithPlayerDP(Coord alien, Box box);

	void validatePlayerPosition(Coord c);
	
	int getFrameNumber();
}