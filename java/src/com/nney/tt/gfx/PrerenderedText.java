package com.nney.tt.gfx;

public interface PrerenderedText extends Disposable {
	/**
	 * How wide is this thing?
	 * 
	 * @return The width in pixels.
	 */
	int width();

	/**
	 * How high is this thing?
	 * 
	 * @return The height in pixels.
	 */
	int height();

	/**
	 * Draw it.
	 * 
	 * @param x
	 *            The x coordinate to draw it at.
	 * @param y
	 *            The y coordinate to draw it at.
	 */
	void draw(int x, int y);
}