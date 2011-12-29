package com.nney.tt.gfx;

public interface BlocksHolder extends Disposable {
	/**
	 * Slow drawing of a single block.
	 * 
	 * @param blocks
	 *            A single block number.
	 * @param dx
	 *            A screen coordinate at which to draw it.
	 * @param dy
	 */
	void draw(int block, int dx, int dy);

	/**
	 * Optimised drawing of a horizontal strip of blocks.
	 * 
	 * @param blocks
	 *            An array of block numbers.
	 * @param dx
	 *            A screen coordinate at which to draw them.
	 * @param dy
	 */
	void draw(int[] blocks, int dx, int dy);

	/**
	 * How many blocks do we have?
	 * 
	 * @return
	 */
	int getBlockCount();
}