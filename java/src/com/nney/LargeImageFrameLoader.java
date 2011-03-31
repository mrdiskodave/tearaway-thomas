package com.nney;

import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

/**
 * Here is one way of loading Sprites.
 * 
 * We load a large image which must have odd (i.e. not even) dimensions so that
 * it has an obvious centre pixel. The centre pixel will be the Sprite's "handle".
 * Next, the image has all the transparency shaved off the top, bottom, left and
 * right before being returned as the {@link Sprite}.
 * 
 * The large image will need to be in some format that supports transparency.
 * PNG definitely works.
 */
public class LargeImageFrameLoader {
	public static Sprite load(Openable data) {
		byte[] someRawGraphicsFile = OpenableTools.mustLoad(data);
		return spriteFromLargeImage(someRawGraphicsFile);
	}

	private static Sprite spriteFromLargeImage(byte[] someRawGraphicsFile) {
		SimpleImage si = new SimpleImage(someRawGraphicsFile);

//		// other FrameLoaders (if there ever are any!) will have to think about how to implement this
//		// or maybe we generalise it (so it can move the handle) and we move it inside Bob ctor)
//		if (s.fx==SpriteFX.MIRROR) {
//			final int w = si.getWidth();
//			SimpleImage.MovePixel pixelMovement = new SimpleImage.MovePixel() {
//				@Override
//				public void move(Coord c) {
//					c.x = w-1-c.x;
//				}};
//			si = si.movePixels(pixelMovement);
//		}

		// Establish where the handle is
		assert si.getWidth() % 2 == 1;
		assert si.getHeight() % 2 == 1;
		int handleX = si.getWidth() / 2;
		int handleY = si.getHeight() / 2;

		// Establish the bounds of the bob
		// (as it is surrounded on all four sides by transparency)
		Bounds bounds = si.getBounds();

		// Crop it to those bounds
		si = si.view(bounds);
		handleX -= bounds.left;
		handleY -= bounds.top;

		// and that is us!
		return new Sprite(si, handleX, handleY);
	}
}
