package com.nney.tt.sprites;

import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

/**
 * Here is one way of loading Sprites.
 * 
 * We load a large image which must have odd (i.e. not even) dimensions so that
 * it has an obvious centre pixel. The centre pixel will be the Sprite's
 * "handle". Next, the image has all the transparency shaved off the top,
 * bottom, left and right before being returned as the {@link Sprite}.
 * 
 * The large image will need to be in some format that supports transparency.
 * PNG definitely works.
 */
public class LargeImageFrameLoader {

	public static Sprite load(GraphicsContext gc, Openable data, boolean makeWhiteVersion) {
		byte[] someRawGraphicsFile = OpenableTools.mustLoad(data);
		SimpleImage si = new SimpleImage(someRawGraphicsFile);

		// Establish where the handle is
		assert si.width() % 2 == 1;
		assert si.height() % 2 == 1;
		int handleX = si.width() / 2;
		int handleY = si.height() / 2;

		// Establish the bounds of the bob
		// (as it is surrounded on all four sides by transparency)
		Bounds bounds = si.bounds();

		// Crop it to those bounds
		si = si.view(bounds);
		handleX -= bounds.left;
		handleY -= bounds.top;

		// and that is us!
		return new Sprite(gc, si, handleX, handleY, makeWhiteVersion);
	}

}
