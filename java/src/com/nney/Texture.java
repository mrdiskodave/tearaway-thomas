package com.nney;

import java.nio.ByteBuffer;

import org.lwjgl.opengl.GL11;

public class Texture {
	private static final boolean SHOW_BOUNDING_BOX = false;

	private int textureId;
	private int textureW;
	private int textureH;

	private int imageW;
	private int imageH;

	private int pow2(int x) {
		int a = 2;
		while (x > a) {
			a <<= 1;
		}
		return a;
	}

	Texture(SimpleImage si) {
		// TODO: maybe don't store image dimensions here
		imageW = si.getWidth();
		imageH = si.getHeight();
		
		// TODO: do we always need to do this?
		textureW = pow2(imageW);
		textureH = pow2(imageH);
		
		// ... assuming that we do we can at least not blit the whole thing
//		textCornerX = (float) imageW / textureW;
//		textCornerY = (float) imageH / textureH;

		ByteBuffer buffer = ByteBuffer.allocateDirect(textureW * textureH * 4);

		if (SHOW_BOUNDING_BOX) {
			for (int x = 0; x < textureW * textureH; x++) {
				buffer.put((byte) 0xff);
				buffer.put((byte) 0);
				buffer.put((byte) 0);
				buffer.put((byte) 0xff);
			}
		}

		for (int y = 0; y < si.getHeight(); y++) {
			for (int x = 0; x < si.getWidth(); x++) {
				int p = si.getPixel(x, y);
				int a = p >> 3 * 8;
				if (a != 0) {
					int r = p >> 2 * 8;
					int g = p >> 1 * 8;
					int b = p >> 0 * 8;
					buffer.position((y * textureW + x) * 4);
					buffer.put((byte) r);
					buffer.put((byte) g);
					buffer.put((byte) b);
					buffer.put((byte) a);
				}
			}
		}
		buffer.rewind();

		GlTools.configureFor2dBobs();
		textureId = GL11.glGenTextures();
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, GL11.GL_RGBA8, textureW, textureH, 0,
				GL11.GL_RGBA, GL11.GL_UNSIGNED_BYTE, buffer);
	}

	public void draw(int screenX, int screenY) {
		draw(screenX, screenY, 0, 0, imageW, imageH);
	}

	public void draw(int screenX, int screenY, int textureX, int textureY, int w, int h) {
		float fleft = (float) textureX / textureW;
		float ftop = (float) textureY / textureH;
		float fright = (float) (textureX+w) / textureW;
		float fbottom = (float) (textureY+h) / textureH;
		
		GL11.glBindTexture(GL11.GL_TEXTURE_2D, textureId);
		GL11.glBegin(GL11.GL_QUADS);
		GL11.glTexCoord2f(fleft, ftop);
		GL11.glVertex2i(screenX, screenY);
		GL11.glTexCoord2f(fright, ftop);
		GL11.glVertex2i(screenX + w, screenY);
		GL11.glTexCoord2f(fright, fbottom);
		GL11.glVertex2i(screenX + w, screenY + h);
		GL11.glTexCoord2f(fleft, fbottom);
		GL11.glVertex2i(screenX, screenY + h);
		GL11.glEnd();
		
	}

}
