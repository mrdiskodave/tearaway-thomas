package com.nney.tt;

import static org.lwjgl.opengl.GL11.GL_COLOR_BUFFER_BIT;
import static org.lwjgl.opengl.GL11.glClear;

import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

public class GraphicsContext {
	void drawSolidRect(int x, int y, int w, int h, int col) {
		GlTools.reset();
		GlTools.selectColor(col);
		GL11.glRecti(x, y, x + w, y + h);
		GlTools.configureFor2dBobs();
	}

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
	
	public void drawHollowRect(int x, int y, int w, int h, int c) {
		drawSolidRect(x, y, w, 1, c);
		drawSolidRect(x, y, 1, h, c);
		drawSolidRect(x + w - 1, y, 1, h, c);
		drawSolidRect(x, y + h - 1, w, 1, c);
	}
	
	public Captured capture(SimpleImage i) {
		final GlTexture gt = new GlTexture(i);
		return new Captured() {
			@Override
			public void draw(int dx, int dy) {
				gt.draw(dx, dy);
			}
			@Override
			public void dispose() {
				gt.dispose();
			}};
	}

	public void cls() {
		glClear(GL_COLOR_BUFFER_BIT);
	}

}
