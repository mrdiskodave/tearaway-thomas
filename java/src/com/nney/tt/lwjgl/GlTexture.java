package com.nney.tt.lwjgl;

import java.nio.ByteBuffer;

import org.lwjgl.opengl.EXTFramebufferObject;
import org.lwjgl.opengl.GL11;
import org.lwjgl.opengl.GL12;
import org.lwjgl.opengl.Util;

import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.mbr.MustBeReleased;

public final class GlTexture implements Blitable, PrerenderedText {
	final private MustBeReleased mbr = new MustBeReleased();
	final private int textureId;
	final private int textureW;
	final private int textureH;

	final private int imageW;
	final private int imageH;

	public GlTexture(SimpleImage si) {
		this(si, false);
	}

	public GlTexture(SimpleImage si, boolean mono) {
		this(si, si.width(), si.height(), mono);
	}

	public GlTexture(int w, int h) {
		this(null, w, h, false);
	}

	private GlTexture(SimpleImage si, int w, int h, boolean mono) {
		int theirFormat = mono ? GL11.GL_ALPHA : GL11.GL_RGBA8;

		imageW = w;
		imageH = h;

		if (LwjglMain.GL_ARB_texture_non_power_of_two) {
			textureW = imageW;
			textureH = imageH;
		}
		else {
			textureW = GlTools.pow2(imageW);
			textureH = GlTools.pow2(imageH);
		}

		textureId = GlTools.genTextureName();
		assert textureId != 0;
		bindTexture();
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_S, GL12.GL_CLAMP_TO_EDGE);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_WRAP_T, GL12.GL_CLAMP_TO_EDGE);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MIN_FILTER, GL11.GL_NEAREST);
		GL11.glTexParameteri(GL11.GL_TEXTURE_2D, GL11.GL_TEXTURE_MAG_FILTER, GL11.GL_NEAREST);
		ByteBuffer bb = GlTools.makeByteBufferRGBA(textureW, textureH);
		if (si != null) GlTools.preLoadRGBA(bb, si);
		GL11.glTexImage2D(GL11.GL_TEXTURE_2D, 0, theirFormat, textureW, textureH, 0, GL11.GL_RGBA,
				GL11.GL_UNSIGNED_BYTE, bb);
		Util.checkGLError();
	}

	/**
	 * Draw texture 1:1 at the given screen position.
	 * 
	 * @param screenX
	 * @param screenY
	 */
	@Override
	public void draw(int screenX, int screenY) {
		if (LwjglMain.GL_ARB_texture_non_power_of_two) {
			int screenRight = screenX + textureW;
			int screenBottom = screenY + textureH;
			bindTexture();
			GL11.glBegin(GL11.GL_QUADS);
			GL11.glTexCoord2f(0f, 0f);
			GL11.glVertex2i(screenX, screenY);
			GL11.glTexCoord2f(1f, 0f);
			GL11.glVertex2i(screenRight, screenY);
			GL11.glTexCoord2f(1f, 1f);
			GL11.glVertex2i(screenRight, screenBottom);
			GL11.glTexCoord2f(0f, 1f);
			GL11.glVertex2i(screenX, screenBottom);
			GL11.glEnd();
		}
		else {
			draw(screenX, screenY, 0, 0, imageW, imageH);
		}
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
		float textureRightf = (float) (textureX + tw) / textureW;
		float textureBottomf = (float) (textureY + th) / textureH;
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

	@Override
	public void dispose() {
		GL11.glDeleteTextures(textureId);
		mbr.release();
	}

	@Override
	public int width() {
		return imageW;
	}

	@Override
	public int height() {
		return imageH;
	}

	public void attachToFBO(int myFBOId) {
		EXTFramebufferObject.glBindFramebufferEXT(EXTFramebufferObject.GL_FRAMEBUFFER_EXT, myFBOId);
		EXTFramebufferObject.glFramebufferTexture2DEXT(EXTFramebufferObject.GL_FRAMEBUFFER_EXT,
				EXTFramebufferObject.GL_COLOR_ATTACHMENT0_EXT, GL11.GL_TEXTURE_2D, textureId, 0);

		EXTFramebufferObject.glBindFramebufferEXT(EXTFramebufferObject.GL_FRAMEBUFFER_EXT, myFBOId);
		GlTools.completeness(myFBOId);
	}
}
