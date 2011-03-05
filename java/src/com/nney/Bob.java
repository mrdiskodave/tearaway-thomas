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
	private Bob(SimpleImage si, int handleX, int handleY) {
		this.handleX = handleX;
		this.handleY = handleY;
		this.texture = new Texture(si);
	}

	/**
	 * Make a {@link Bob} from a large image.
	 * 
	 * The image must have odd dimensions (i.e. not even) so that it has an
	 * obvious centre pixel. The centre pixel will be the bob's "handle". Next,
	 * the image has all the transparency shaved off the top, bottom, left and
	 * right before being returned as a {@link Bob}.
	 * 
	 * @param someRawGraphicsFile
	 *            All the bytes from a graphics file. It'll need to support
	 *            transparency. PNG definitely works.
	 */
	static Bob fromLargeImage(byte[] someRawGraphicsFile) {
		SimpleImage si = new SimpleImage(someRawGraphicsFile);

		// Establish where the handle is
		assert si.getWidth() % 2 == 1;
		assert si.getHeight() % 2 == 1;
		int handleX = si.getWidth() / 2;
		int handleY = si.getHeight() / 2;

		// Establish the bounds of the bob
		// (as it is surrounded on all four sides by transparency)
		Bounds bounds = si.getBounds();

		// Crop it to those bounds
		si = si.crop(bounds);
		handleX -= bounds.left;
		handleY -= bounds.top;

		// and that is us!
		return new Bob(si, handleX, handleY);
	}

	/**
	 * Draw the bob.
	 * 
	 * @param dx Where to put the handle (the rest of the bob is drawn around it, of course).
	 * @param dy
	 */
	public void draw(int dx, int dy) {
		dx -= handleX;
		dy -= handleY;
		texture.draw(dx, dy);
	}
}
