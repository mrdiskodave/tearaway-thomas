package com.nney.tt.gfx;

import org.lwjgl.opengl.GL11;
import org.lwjgl.opengl.GL12;

public class GlTexture {
	private int textureId;
	private int textureW;
	private int textureH;

	private int imageW;
	private int imageH;

	public GlTexture(SimpleImage si) {
		this(si, GL11.GL_RGBA8);
	}
	
	// TODO: ! just take a boolean hint about it being grayscale?
	public GlTexture(SimpleImage si, int theirFormat) {
		// TODO: maybe don't store image dimensions here
		imageW = si.getWidth();
		imageH = si.getHeight();
		
		// TODO: do we always need to do this?
		textureW = GlTools.pow2(imageW);
		textureH = GlTools.pow2(imageH);
		
		textureId = GL11.glGenTextures();
		assert textureId!=0;
		bindTexture();
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_S, GL12.GL_CLAMP_TO_EDGE);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_T, GL12.GL_CLAMP_TO_EDGE); // gosh GL12!
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_NEAREST);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_NEAREST);
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, theirFormat, textureW, textureH, 0,
				GL11.GL_RGBA, GL11.GL_UNSIGNED_BYTE, GlTools.makeByteBuffer(si, textureW, textureH));
	}

	/**
	 * Draw texture 1:1 at the given screen position.
	 * 
	 * @param screenX
	 * @param screenY
	 */
	public void draw(int screenX, int screenY) {
		draw(screenX, screenY, 0, 0, imageW, imageH);
	}

	public void draw(int screenX, int screenY, int textureX, int textureY, int tw, int th) {
		stretchDraw(screenX, screenY, tw, th, textureX, textureY, tw, th);
	}
	
	public void stretchDraw(int screenX, int screenY, int sw, int sh, int textureX, int textureY, int tw, int th) {
		bindTexture();
		GL11.glBegin(GL11.GL_QUADS);
		drawQuad(screenX, screenY, sw, sh, textureX, textureY, tw, th);
		GL11.glEnd();
	}

	public void bindTexture() {
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
	}

	public void drawQuad(int screenX, int screenY, int screenW, int screenH, int textureX, int textureY, int tw, int th) {
		float textureLeftf = (float) textureX / textureW;
		float textureTopf = (float) textureY / textureH;
		float textureRightf = (float) (textureX+tw) / textureW;
		float textureBottomf = (float) (textureY+th) / textureH;
		int screenRight = screenX + screenW;
		int screenBottom = screenY + screenH;

		GL11.glTexCoord2f(textureLeftf, textureTopf);
		GL11.glVertex2i(screenX, screenY);
		GL11.glTexCoord2f(textureRightf, textureTopf);
		GL11.glVertex2i(screenRight, screenY);
		GL11.glTexCoord2f(textureRightf, textureBottomf);
		GL11.glVertex2i(screenRight, screenBottom);
		GL11.glTexCoord2f(textureLeftf, textureBottomf);
		GL11.glVertex2i(screenX, screenBottom);
	}
	
	public void dispose() {
		GL11.glDeleteTextures(textureId);
	}
	
	public int getWidth() {
		return imageW;
	}
	
	public int getHieght() {
		return imageH;
	}
}
