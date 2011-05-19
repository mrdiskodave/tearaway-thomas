package com.nney.tt.gfx;

public interface PrerenderedText {
	/**
	 * How wide is the whole text?
	 * @return The width in pixels.
	 */
	int width();

	/**
	 * How high is the whole text?
	 * @return The height in pixels.
	 */
	int height();
	
	/**
	 * Draw it on the screen.
	 * @param x The x coordinate to draw it at.
	 * @param y The y coordinate to draw it at.
	 */
	void draw(int x, int y);

	/**
	 * Release any resources associated with this object.
	 */
	void dispose();


}