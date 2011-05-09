package com.nney.tt.gfx;

import java.nio.ByteBuffer;

import org.lwjgl.opengl.GL11;

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
		
	}
	
	public static void configureFor2dBobs() {
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);

		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, GL11.GL_REPLACE);
	}

	public static void configureForFont(boolean mono, int fg) {
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);

		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, mono ? GL11.GL_REPLACE : GL11.GL_MODULATE);
		selectColor(fg);
	}
	
	

	public static void selectColor(int fg) {
		int r = ( fg >> 2*8 ) & 0xff;
		int g = ( fg >> 8 ) & 0xff;
		int b = ( fg ) & 0xff;
		GL11.glColor3ub((byte)r, (byte)g, (byte)b);
	}


	public static ByteBuffer makeByteBuffer(SimpleImage si, int w, int h) {
		ByteBuffer buffer = ByteBuffer.allocateDirect(w * h * 4);
		for (int y = 0; y < si.getHeight(); y++) {
			for (int x = 0; x < si.getWidth(); x++) {
				int p = si.getPixel(x, y);
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
		return buffer;
	}

	public static ByteBuffer makeByteBuffer(SimpleImage si) {
		return makeByteBuffer(si, si.getWidth(), si.getHeight());
	}
	
	
	
	static public int discoverShift(int v) {
		for (int x=0; x<32; x++) {
			int a = 1<<x;
			if (a==v) return x;
		}
		assert false : v;
		return 0;
	}
	
	public static int pow2(int x) {
		int a = 2;
		while (x > a) {
			a <<= 1;
		}
		return a;
	}
}
