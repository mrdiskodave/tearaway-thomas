package com.nney.tt;

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
		mapSourceInBlocks = mapSourceInPixels / Main.BLOCK_SIZE;
		initialPixelDestination = -(mapSourceInPixels & Main.BLOCK_MASK);
		// what is the minimum number of blocks to cover those pixels?
		int blockCount = TTMath.roundUpDiv(screenSizeInPixels, Main.BLOCK_SIZE);
		// if that doesn't get us all the way across the visible screen ..
		if (initialPixelDestination + blockCount * Main.BLOCK_SIZE < screenSizeInPixels) {
			// .. then we'll need one more
			blockCount++;
		}
		this.blockCount = blockCount;
	}
}
