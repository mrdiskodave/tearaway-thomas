package com.nney.tt.lwjgl;

import java.nio.ByteBuffer;
import java.nio.IntBuffer;

import javax.management.RuntimeErrorException;

import org.lwjgl.BufferUtils;
import org.lwjgl.opengl.EXTFramebufferObject;
import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.SimpleImage;

public class GlTools {
	public static void reset() {
		// reset
		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
		GL11.glListBase(0);
		GL11.glDisable(GL11.GL_TEXTURE_GEN_S);
		GL11.glDisable(GL11.GL_TEXTURE_GEN_T);

		// common to all three configurations:
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);

		// all code that uses opengl can expect to find it
		// configuredFor2dBobs() and
		// in glMatrixMode(GL11.GL_MODELVIEW)
	}

	public static void configureFor2dBobs() {
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_REPLACE);
	}

	public static void configureFor2dRect(int col) {
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_MODULATE);
		GlTools.selectColor(col);
	}

	public static void configureForFont(boolean mono, int fg) {
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, mono ? GL11.GL_REPLACE : GL11.GL_MODULATE);
		selectColor(0xff000000 | fg);
	}

	public static void selectColor(int fg) {
		int a = (fg >> 3 * 8) & 0xff;
		int r = (fg >> 2 * 8) & 0xff;
		int g = (fg >> 8) & 0xff;
		int b = (fg) & 0xff;
		GL11.glColor4ub((byte) r, (byte) g, (byte) b, (byte) a);
	}

	public static ByteBuffer makeByteBufferRGBA(int w, int h) {
		return ByteBuffer.allocateDirect(w * h * 4);
	}

	public static void preLoadRGBA(ByteBuffer buffer, SimpleImage preLoad) {
		int w = preLoad.width();
		int h = preLoad.height();
		for (int y = 0; y < h; y++) {
			for (int x = 0; x < w; x++) {
				int p = preLoad.get(x, y);
				int a = p >> 3 * 8;
				if (a != 0) {
					int r = p >> 2 * 8;
					int g = p >> 1 * 8;
					int b = p >> 0 * 8;
					buffer.position((y * w + x) * 4);
					buffer.put((byte) r);
					buffer.put((byte) g);
					buffer.put((byte) b);
					buffer.put((byte) a);
				}
			}
		}
		buffer.rewind();
	}

	public static int pow2(int x) {
		int a = 2;
		while (x > a) {
			a <<= 1;
		}
		return a;
	}

	public static void completeness(int myFBOId) {
		int framebuffer = EXTFramebufferObject.glCheckFramebufferStatusEXT(EXTFramebufferObject.GL_FRAMEBUFFER_EXT);
		switch (framebuffer) {
		case EXTFramebufferObject.GL_FRAMEBUFFER_COMPLETE_EXT:
			break;
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT_EXT exception");
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_MISSING_ATTACHMENT_EXT exception");
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_DIMENSIONS_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_DIMENSIONS_EXT exception");
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_DRAW_BUFFER_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_DRAW_BUFFER_EXT exception");
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_FORMATS_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_FORMATS_EXT exception");
		case EXTFramebufferObject.GL_FRAMEBUFFER_INCOMPLETE_READ_BUFFER_EXT:
			err("FrameBuffer: " + myFBOId + ", has caused a GL_FRAMEBUFFER_INCOMPLETE_READ_BUFFER_EXT exception");
		default:
			err("Unexpected reply from glCheckFramebufferStatusEXT: " + framebuffer);
		}
	}

	public static int genTextureName() {
		int r = GL11.glGenTextures();
		if (r == 0) {
			err("Ran out of texture names");
		}
		return r;
	}

	public static int genBufferName() {
		IntBuffer buffer = BufferUtils.createIntBuffer(1);
		EXTFramebufferObject.glGenFramebuffersEXT(buffer); // generate
		int r = buffer.get();
		if (r == 0) {
			err("Ran out of FBO names");
		}
		return r;
	}

	public static void err(String msg) {
		throw new RuntimeException("OpenGL problem: " + msg);
	}
}
