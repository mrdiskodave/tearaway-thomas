package com.nney.tt.j2d;

import java.awt.AlphaComposite;
import java.awt.Composite;
import java.awt.Graphics2D;
import java.awt.image.BufferedImage;

import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.gfx.SimpleImage;

/**
 * A sprite (or pre-rendered piece of text) held as a Java2D image.
 *
 * The pure-Java replacement for GlTexture.
 */
final class J2dImage implements Blitable, PrerenderedText {
	private final J2dGraphicsContext gc;
	final BufferedImage image;

	J2dImage(J2dGraphicsContext gc, BufferedImage image) {
		this.gc = gc;
		this.image = image;
	}

	J2dImage(J2dGraphicsContext gc, SimpleImage si) {
		this(gc, toBufferedImage(si));
	}

	static BufferedImage toBufferedImage(SimpleImage si) {
		int w = si.width();
		int h = si.height();
		BufferedImage bi = new BufferedImage(Math.max(1, w), Math.max(1, h), BufferedImage.TYPE_INT_ARGB);
		int[] row = new int[w];
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				row[x] = si.get(x, y);
			}
			bi.setRGB(0, y, w, 1, row, 0, w);
		}
		return bi;
	}

	@Override
	public void draw(int dx, int dy) {
		gc.g().drawImage(image, dx, dy, null);
	}

	@Override
	public void drawTranslucent(int dx, int dy, float opacity) {
		Graphics2D g = gc.g();
		Composite was = g.getComposite();
		g.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, opacity));
		g.drawImage(image, dx, dy, null);
		g.setComposite(was);
	}

	@Override
	public int width() {
		return image.getWidth();
	}

	@Override
	public int height() {
		return image.getHeight();
	}

	@Override
	public void dispose() {
		image.flush();
	}
}
