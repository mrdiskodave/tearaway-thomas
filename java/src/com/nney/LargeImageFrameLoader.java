package com.nney;

import com.nney.utils.FileOpenable;
import com.nney.utils.OpenableTools;

/**
 * Here is one way of loading frames.
 * 
 * We load a large image which must have odd (i.e. not even) dimensions so that
 * it has an obvious centre pixel. The centre pixel will be the bobs "handle".
 * Next, the image has all the transparency shaved off the top, bottom, left and
 * right before being returned as the {@link Bob}.
 * 
 * The large image will need to be in some format that supports transparency.
 * PNG definitely works.
 */
public abstract class LargeImageFrameLoader implements FrameLoader {
	@Override
	public Bob load(Frame f) {
		FileOpenable data = loadData(f);
		return load(data);
	}

	abstract FileOpenable loadData(Frame f);

	protected Bob load(FileOpenable openable) {
		byte[] someRawGraphicsFile = OpenableTools.load(openable);
		return bobFromLargeImage(someRawGraphicsFile);
	}

	private static Bob bobFromLargeImage(byte[] someRawGraphicsFile) {
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
}
