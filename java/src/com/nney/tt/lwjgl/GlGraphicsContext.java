package com.nney.tt.lwjgl;

import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class GlGraphicsContext implements GraphicsContext {
	@Override
	public void fillRectangle(int x, int y, int w, int h, int col) {
		GlTools.configureFor2dRect(col);
		GL11.glRecti(x, y, x + w, y + h);
		GlTools.configureFor2dBobs();
	}

	@Override
	public Horizon loadHorizon(Openable ho) {
		final GlTexture gt = new GlTexture(new SimpleImage(OpenableTools.mustLoad(ho)));
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_LINEAR);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_LINEAR);

		return new Horizon() {
			@Override
			public void draw() {
				gt.stretchDraw(0, 0, Main.SCREEN_WIDTH, Main.SCREEN_HEIGHT, 0, 0, gt.getWidth(), gt.getHieght());
			}

			@Override
			public void dispose() {
				gt.dispose();
			}
		};
	}

	@Override
	public Blitable createBlitable(SimpleImage i) {
		final GlTexture gt = new GlTexture(i);
		return new Blitable() {
			@Override
			public void draw(int dx, int dy) {
				gt.draw(dx, dy);
			}

			@Override
			public void dispose() {
				gt.dispose();
			}
		};
	}

	@Override
	public BlocksHolder createBlocksHolder(BlockSource bs) {
		return new GlBlocksHolder(bs);
	}

	@Override
	public Font createFont(byte[] data, int miniW, int miniH, boolean proportional, String characters) {
		return new GlFont(data, miniW, miniH, proportional, characters);
	}

	@Override
	public int screenWidth() {
		return Main.SCREEN_WIDTH;
	}

	@Override
	public int screenHeight() {
		return Main.SCREEN_HEIGHT;
	}
	
	@Override
	public void antiCircle(int radius, int x, int y, int c) {
		int w = screenWidth();
		int h = screenHeight();
		int steps = Math.max(10, radius / 15);
		GlTools.configureFor2dRect(c);

		int[] v = new int[(steps + 2) * 2];
		int p = 0;
		v[p++] = radius;
		v[p++] = radius;
		for (int a = 0; a < steps + 1; a++) {
			double angle = ((Math.PI / 2.0) * a) / steps;
			v[p++] = (int) (Math.cos(angle) * radius);
			v[p++] = (int) (Math.sin(angle) * radius);
		}

		drawFan(v, x, y, 1, 1);
		drawFan(v, x, y, -1, 1);
		drawFan(v, x, y, 1, -1);
		drawFan(v, x, y, -1, -1);

		// everything above
		boxFill(0, 0, w, y - radius);
		// everything below
		boxFill(0, y + radius, w, h);
		// bit to the left
		boxFill(0, y - radius, x - radius, y + radius);
		// bit to the right
		boxFill(x + radius, y - radius, w, y + radius);

		GlTools.configureFor2dBobs();
	}

	private void boxFill(int t, int l, int b, int r) {
		// gc.fillRectangle(t, l, b - t, r - l, c);
		if (b <= t || r <= l) return;
		GL11.glRecti(t, l, b, r);
	}

	private void drawFan(int[] v, int x, int y, int ix, int iy) {
		GL11.glBegin(GL11.GL_TRIANGLE_FAN);
		for (int p = 0; p < v.length; p += 2) {
			GL11.glVertex2i(x + v[p] * ix, y + v[p + 1] * iy);
		}
		GL11.glEnd();
	}
}
