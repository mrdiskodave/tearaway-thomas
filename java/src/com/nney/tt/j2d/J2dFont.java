package com.nney.tt.j2d;

import java.awt.Graphics2D;
import java.awt.image.BufferedImage;
import java.util.HashMap;

import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.PartialFontImpl;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.gfx.RawFont;
import com.nney.tt.gfx.SimpleImage;

/**
 * Bitmap font drawing.
 *
 * Matches the OpenGL version's colouring rules: a two-colour ("mono") font is
 * drawn in the foreground colour using the glyph's alpha as a mask; a
 * multi-colour font has its colours multiplied by the foreground colour.
 */
final class J2dFont extends PartialFontImpl {
	private final J2dGraphicsContext gc;
	private SimpleImage content;
	private final HashMap<Integer, BufferedImage> tinted = new HashMap<Integer, BufferedImage>();
	private BufferedImage current;

	J2dFont(J2dGraphicsContext gc, RawFont rf) {
		super(rf);
		this.gc = gc;
	}

	@Override
	protected void renderContent(SimpleImage content) {
		// called from our superclass constructor, so keep this simple
		this.content = content;
	}

	private BufferedImage tint(int fg) {
		fg |= 0xff000000;
		BufferedImage bi = tinted.get(fg);
		if (bi != null) return bi;

		int w = content.width();
		int h = content.height();
		bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		int fr = (fg >> 16) & 0xff;
		int fgg = (fg >> 8) & 0xff;
		int fb = fg & 0xff;
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				int p = content.get(x, y);
				int a = (p >>> 24) & 0xff;
				int out;
				if (a == 0) {
					out = 0;
				}
				else if (mono) {
					out = (a << 24) | (fg & 0xffffff);
				}
				else {
					int r = ((p >> 16) & 0xff) * fr / 255;
					int g = ((p >> 8) & 0xff) * fgg / 255;
					int b = (p & 0xff) * fb / 255;
					out = (a << 24) | (r << 16) | (g << 8) | b;
				}
				bi.setRGB(x, y, out);
			}
		}
		tinted.put(fg, bi);
		return bi;
	}

	@Override
	protected void startDrawing(int fg) {
		current = tint(fg);
	}

	@Override
	protected void drawChar(int dx, int dy, Bounds z) {
		int w = z.width / scaleDown;
		int h = z.height / scaleDown;
		gc.g().drawImage(current, dx, dy, dx + w, dy + h, z.left, z.top, z.left + z.width, z.top + z.height, null);
	}

	@Override
	protected void stopDrawing() {
		current = null;
	}

	@Override
	public PrerenderedText preRender(int fg, int kern, String text) {
		int w = Math.max(1, computeWidth(kern, text));
		int h = Math.max(1, charHeight());
		BufferedImage bi = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g = bi.createGraphics();
		gc.pushTarget(g);
		try {
			draw(0, 0, fg, kern, text);
		}
		finally {
			gc.popTarget();
			g.dispose();
		}
		return new J2dImage(gc, bi);
	}

	@Override
	public void dispose() {
		for (BufferedImage bi : tinted.values()) {
			bi.flush();
		}
		tinted.clear();
	}
}
