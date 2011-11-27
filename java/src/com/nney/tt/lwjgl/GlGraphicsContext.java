package com.nney.tt.lwjgl;

import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.RawFont;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public final class GlGraphicsContext implements GraphicsContext {
	private final Runnable updateInputs;
	private final Runnable onActivate;
	private final int fps;

	GlGraphicsContext(int fps, Runnable updateInputs, Runnable onActivate) {
		this.fps = fps;
		this.updateInputs = updateInputs;
		this.onActivate = onActivate;
	}

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
				gt.stretchDraw(0, 0, LwjglMain.SCREEN_WIDTH, LwjglMain.SCREEN_HEIGHT, 0, 0, gt.width(), gt.height());
			}

			@Override
			public void dispose() {
				gt.dispose();
			}
		};
	}

	@Override
	public Blitable createBlitable(SimpleImage i) {
		return new GlTexture(i);
	}

	@Override
	public BlocksHolder createBlocksHolder(BlockSource bs) {
		return new GlBlocksHolder(bs);
	}

	@Override
	public Font createFont(RawFont rf) {
		return new GlFont(rf);
	}

	@Override
	public int screenWidth() {
		return LwjglMain.SCREEN_WIDTH;
	}

	@Override
	public int screenHeight() {
		return LwjglMain.SCREEN_HEIGHT;
	}

	@Override
	public void aperture(int radius, int x, int y, int c) {
		GlTools.configureFor2dRect(c);

		int w = screenWidth();
		int h = screenHeight();
		int steps = Math.max(12, radius / 15);

		int[] v = new int[(steps + 2) * 2];
		int p = 0;
		v[p++] = radius;
		v[p++] = radius;
		v[p++] = radius;
		v[p++] = 0;
		for (int a = 1; a <= steps; a++) {
			double angle = ((Math.PI / 2.0) * a) / steps;
			int vx = (int) (Math.round(Math.cos(angle) * radius));
			int vy = (int) (Math.round(Math.sin(angle) * radius));
			v[p++] = vx;
			v[p++] = vy;
		}
		// it gets pointy at the top bottom left and right
		// because cos and sin truncated spikes into one just at 0deg only
		// the Math.round is there to stop that.

		// for (int a = 0; a <= steps; a++) {
		// System.out.println(String.format("%s,%s,%s", a, v[a*2], v[a*2+1]));
		// }
		// System.out.println("---");

		// TODO: teach it to GL then replay it under different rotations?
		drawFan(v, x, y, 1, 1);
		drawFan(v, x, y, -1, 1);
		drawFan(v, x, y, 1, -1);
		drawFan(v, x, y, -1, -1);

		// GlTools.configureFor2dRect(0xffff0000);

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

	boolean inside;
	boolean active = true;

	@Override
	public void beginDrawing() {
		assert !inside;
		inside = true;
		Display.sync(fps);
		updateInputs.run();
		GlTools.configureFor2dBobs();
	}

	@Override
	public void endDrawing() {
		assert inside;
		inside = false;
		Display.update();
		if (Display.isCloseRequested()) {
			throw new LwjglMain.ExitException();
		}
		if (Display.isActive()) {
			if (!active) {
				active = true;
				onActivate.run();
			}
		}
		else {
			active = false;
		}
		Thread.yield();
	}
}
