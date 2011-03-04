package com.nney;


public class Bob {
	private final int subX;
	private final int subY;
	private Texture texture;

	public Bob(int subX, int subY, SimpleImage si) {
		this.subX = subX;
		this.subY = subY;
		this.texture = new Texture(si);
	}

	/**
	 * Make a bob from a large image.
	 * 
	 * The image must have odd (not even) dimensions so that it has an obvious
	 * centre pixel. The centre pixel is where the bob is handled by. When you
	 * ask to paint it at <code>x/y</code> you will be positioning it on screen
	 * by that centre pixel. Next, the image has all the transparency shaved off
	 * the top, bottom, left and right before being stored away for later use.
	 * 
	 * @param someRawGraphicsFile
	 *            All the bytes from a graphics file. It'll need to support 
	 *            transparency. PNG definitely works.
	 */
	static Bob fromLargeImage(byte[] someRawGraphicsFile) {
		SimpleImage si = new SimpleImage(someRawGraphicsFile);

		assert si.getWidth() % 2 == 1;
		assert si.getHeight() % 2 == 1;

		Bounds bounds = si.getBounds();

		int midX = si.getWidth() / 2;
		int midY = si.getHeight() / 2;

		int subX = midX - bounds.left;
		int subY = midY - bounds.top;

		si = si.crop(bounds);

		return new Bob(subX, subY, si);
	}

	public void draw(int dx, int dy) {
		dx -= subX;
		dy -= subY;
		texture.draw(dx, dy);
	}

}
