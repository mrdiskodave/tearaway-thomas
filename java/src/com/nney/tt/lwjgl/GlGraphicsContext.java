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
			}};
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
}
