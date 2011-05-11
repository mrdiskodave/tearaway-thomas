package com.nney.tt;

import com.nney.utils.Math2;


/**
 * When drawing the map we generate one of these per map axis. i.e. one for X
 * and one for Y.
 */
public class MapDrawingInfo {
	/**
	 * Where to start writing the blocks graphics? (a screen ordinate)
	 */
	public final int initialPixelDestination;

	/**
	 * Where to start reading the blocks numbers? (a map ordinate)
	 */
	public final int mapSourceInBlocks;

	/**
	 * How many blocks to process?
	 */
	public final int blockCount;

	public MapDrawingInfo(int mapSourceInPixels, int screenSizeInPixels, int mapSizeInPixels) {
		mapSourceInBlocks = mapSourceInPixels / Const.BLOCK_SIZE;
		initialPixelDestination = -(mapSourceInPixels & Const.BLOCK_MASK);
		// what is the minimum number of blocks to cover those pixels?
		int blockCount = Math2.roundUpDiv(screenSizeInPixels, Const.BLOCK_SIZE);
		// if that doesn't get us all the way across the visible screen ..
		if (initialPixelDestination + blockCount * Const.BLOCK_SIZE < screenSizeInPixels) {
			// .. then we'll need one more
			blockCount++;
		}
		this.blockCount = blockCount;
	}
}
