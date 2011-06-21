package com.nney.tt;

import com.nney.tt.map.GameMap;
import com.nney.utils.Math2;

/**
 * Before drawing the {@link GameMap} we generate one of these per ordinate
 * (i.e. one for X and one for Y). They've everything in common there is no
 * sense in coding it twice.
 */
public class ScreenOrdinate {
	/**
	 * Where to start writing the graphics block? (a screen ordinate in pixels)
	 */
	public int initialPixelDestination;

	/**
	 * Where to start reading the block numbers? (a map ordinate in blocks)
	 */
	public int mapSourceInBlocks;

	/**
	 * How many blocks to process? (a count in blocks)
	 */
	public int blockCount;

	/**
	 * A screen ordinate in pixels (or <code>-1</code> if there is no border
	 * needed). If this value is at least zero the borders are <b>on</b> for
	 * this ordinate. The low border goes from 0-
	 * {@link #initialPixelDestination} exclusive and the high border goes from
	 * {@link #highBorderStart} to the high ordinate edge of the screen.
	 */
	public int highBorderStart;

	/**
	 * Make sure given current position is valid and also generate the other
	 * field data in this class. There will be two instances of this class - one
	 * for X and one for Y. All parameters are in pixels.
	 * 
	 * @param current
	 *            The current position (a map ordinate).
	 * @param scrSize
	 *            How big is the screen?
	 * @param mapStart
	 *            Where does the viewable map begin?
	 * @param mapSize
	 *            How big is the map?
	 * @param name
	 *            The name of this ordinate (for debug purposes).
	 * @return A validated position to use in place of the first parameter.
	 */
	public int generate(int current, int scrSize, int mapStart, int mapSize, String name) {
		if (mapSize < scrSize) {
			// System.out.println(String.format("%s: less than the screen",
			// name));

			int pos = (scrSize - mapSize) / 2;
			current = mapStart - pos;
			mapSourceInBlocks = mapStart / Const.BLOCK_SIZE;
			initialPixelDestination = pos;
			blockCount = mapSize / Const.BLOCK_SIZE;

			highBorderStart = initialPixelDestination + mapSize;
		}
		else {
			// System.out.println(String.format("%s: more than the screen",
			// name));
			if (current < mapStart) {
				current = mapStart;
			}
			int max = mapStart + mapSize - scrSize;
			if (current > max) {
				current = max;
			}

			mapSourceInBlocks = current / Const.BLOCK_SIZE;
			initialPixelDestination = -(current & Const.BLOCK_MASK);
			// what is the minimum number of blocks to cover those pixels?
			int blockCount = Math2.roundUpDiv(scrSize, Const.BLOCK_SIZE);
			// if that doesn't get us all the way across the visible screen ..
			if (initialPixelDestination + blockCount * Const.BLOCK_SIZE < scrSize) {
				// .. then we'll need one more
				blockCount++;
			}
			this.blockCount = blockCount;
			highBorderStart = -1;
		}
		return current;
	}
}
