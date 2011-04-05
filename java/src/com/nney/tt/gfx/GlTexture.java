package com.nney.tt.gfx;

import org.lwjgl.opengl.GL11;

public class GlTexture {
	private int textureId;
	private int textureW;
	private int textureH;

	private int imageW;
	private int imageH;

	public GlTexture(SimpleImage si) {
		this(si, GL11.GL_RGBA8);
	}
	
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
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_S, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_T, GL11.GL_CLAMP);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_NEAREST);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_NEAREST);
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, theirFormat, textureW, textureH, 0,
				GL11.GL_RGBA, GL11.GL_UNSIGNED_BYTE, GlTools.makeByteBuffer(si, textureW, textureH));
	}

	public void draw(int screenX, int screenY) {
		draw(screenX, screenY, 0, 0, imageW, imageH);
	}

	public void draw(int screenX, int screenY, int textureX, int textureY, int w, int h) {
		bindTexture();
		GL11.glBegin(GL11.GL_QUADS);
		drawQuad(screenX, screenY, textureX, textureY, w, h);
		GL11.glEnd();
	}

	public void bindTexture() {
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
	}

	public void drawQuad(int screenX, int screenY, int textureX, int textureY, int w, int h) {
		float fleft = (float) textureX / textureW;
		float ftop = (float) textureY / textureH;
		float fright = (float) (textureX+w) / textureW;
		float fbottom = (float) (textureY+h) / textureH;
		GL11.glTexCoord2f(fleft, ftop);
		GL11.glVertex2i(screenX, screenY);
		GL11.glTexCoord2f(fright, ftop);
		GL11.glVertex2i(screenX + w, screenY);
		GL11.glTexCoord2f(fright, fbottom);
		GL11.glVertex2i(screenX + w, screenY + h);
		GL11.glTexCoord2f(fleft, fbottom);
		GL11.glVertex2i(screenX, screenY + h);
	}
	
	public void dispose() {
		GL11.glDeleteTextures(textureId);
	}
}
