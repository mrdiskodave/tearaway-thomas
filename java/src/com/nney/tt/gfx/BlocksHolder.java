package com.nney.tt.gfx;

public interface BlocksHolder extends Disposable {

	/**
	 * Optimised drawing of many blocks at once.
	 * @param blocks An array of block numbers.
	 * @param dx A screen coordinate at which to draw them.
	 * @param dy
	 */
	void draw(int[] blocks, int dx, int dy);

	/**
	 * Slow drawing of a single block.
	 * @param blocks A single block number.
	 * @param dx A screen coordinate at which to draw it.
	 * @param dy
	 */
	void draw(int block, int dx, int dy);

	int getBlockCount();
}