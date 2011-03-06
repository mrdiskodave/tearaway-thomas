package com.nney;

public class Bob {
	private final int handleX;
	private final int handleY;
	private Texture texture;

	/**
	 * Create a {@link Bob}.
	 * @param si An image to use.
	 * @param handleX The x coordinate of the handle within the given image (0 the left). 
	 * @param handleY The y coordinate of the handle within the given image (0 the top).
	 */
	public Bob(SimpleImage si, int handleX, int handleY) {
		this.handleX = handleX;
		this.handleY = handleY;
		this.texture = new Texture(si);
	}

	/**
	 * Draw the bob.
	 * 
	 * @param dx Where to put the handle (the rest of the bob is drawn that location).
	 * @param dy
	 */
	public void draw(int dx, int dy) {
		dx -= handleX;
		dy -= handleY;
		texture.draw(dx, dy);
	}
}
