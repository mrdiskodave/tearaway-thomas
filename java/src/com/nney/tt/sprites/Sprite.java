package com.nney.tt.sprites;

import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;

public class Sprite {
	public final int handleX;
	public final int handleY;
	public final int w;
	public final int h;
	private final GlTexture texture;
	public byte[] rm;

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
	 */
	public Sprite(SimpleImage si, int handleX, int handleY) {
		assert si.getWidth()!=0 && si.getHeight()!=0;
		
		this.handleX = handleX;
		this.handleY = handleY;
		this.w = si.getWidth();
		this.h = si.getHeight();

		byte[] z = new byte[si.getHeight() * 2];
		for (int h = 0; h < si.getHeight(); h++) {
			int r = si.getWidth() - 1;
			while (r!=0 && si.getPixel(r, h) == 0) {
				r--;
			}
			int l = 0;
			// Sprites will never be entirely blank but they may contain blank lines and we need to allow for that
			if (r!=0) {
				while (si.getPixel(l, h) == 0) {
					l++;
				}
			}
			z[2 * h] = (byte) l;
			z[2 * h + 1] = (byte) (r-l+1);
		}
		rm = z;

//		si.changePixels(new ChangePixel() {
//			@Override
//			public int change(int c) {
//				int alpha = c >>> 3 * 8;
//				if (alpha != 0xff) c = 0xff00ffff;
//				return c;
//			}
//		});

		this.texture = new GlTexture(si);
	}

	/**
	 * Draw the bob.
	 * 
	 * @param dx
	 *            Where to put the handle (the rest of the bob is drawn that
	 *            location).
	 * @param dy
	 */
	public void draw(int dx, int dy) {
		dx -= handleX;
		dy -= handleY;
		texture.draw(dx, dy);
	}

	public void dispose() {
		texture.dispose();
	}
}
