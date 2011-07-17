package com.nney.tt.sprites;

import com.nney.tt.geom.Box;
import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.ShowBoundsSip;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.WhiteOutSip;
import com.nney.tt.osd.Component;

public class Sprite implements Disposable {
	public final int handleX;
	public final int handleY;
	public final int w;
	public final int h;
	public final byte[] lineInfo;

	private final Blitable texture;
	private final Blitable whiteVersion;

	static final boolean CTC_SEE_SPRITE_BOX = false;

	/**
	 * Create a {@link Sprite}.
	 * 
	 * @param si
	 *            An image to use.
	 * @param handleX
	 *            The x coordinate of the handle within the given image (0 the
	 *            left).
	 * @param handleY
	 *            The y coordinate of the handle within the given image (0 the
	 *            top).
	 * @param makeWhiteVersion
	 */
	public Sprite(GraphicsContext gc, SimpleImage si, int handleX, int handleY, boolean makeWhiteVersion) {
		assert si.width() != 0 && si.height() != 0;

		this.handleX = handleX;
		this.handleY = handleY;
		this.w = si.width();
		this.h = si.height();
		this.lineInfo = LineInfo.generate(si);

		SimpleImage z = si;

		if (CTC_SEE_SPRITE_BOX) {
			z = si.copy();
			new ShowBoundsSip().process(z);
		}
		this.texture = gc.createBlitable(z);

		if (makeWhiteVersion) {
			new WhiteOutSip().process(si);
			this.whiteVersion = gc.createBlitable(si);
		}
		else {
			this.whiteVersion = null;
		}
	}

	/**
	 * Draw the bob.
	 * 
	 * @param dx
	 *            Where to put the handle (the rest of the bob is drawn that
	 *            location).
	 * @param dy
	 */
	public void drawByHandle(int dx, int dy, boolean drawWhite) {
		dx -= handleX;
		dy -= handleY;
		if (!drawWhite) {
			texture.draw(dx, dy);
		}
		else {
			assert whiteVersion != null;
			whiteVersion.draw(dx, dy);
		}
	}

	@Override
	public void dispose() {
		texture.dispose();
		if (whiteVersion != null) {
			whiteVersion.dispose();
		}
	}

	public Box box() {
		return Box.fromTopLeftAndSize(-handleX, -handleY, w, h);
	}

	public int liftWidth() {
		int indx = handleY * 2;
		int a = lineInfo[indx];
		int b = lineInfo[indx + 1];
		assert handleX == a;
		return b;
	}

	public int width() {
		return w;
	}

	public int height() {
		return h;
	}

	public void draw(int dx, int dy) {
		dx += handleX;
		dy += handleY;
		drawByHandle(dx, dy, false);
	}
}
