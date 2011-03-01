package com.nney;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

public class ColorBox {
	private static final int SCREEN_HEIGHT = 600;
	private static final int SCREEN_WIDTH = 800;

	private void initLwjglDisplay() {
		try {
			Display.setDisplayMode(new DisplayMode(SCREEN_WIDTH, SCREEN_HEIGHT));
			Display.create();
			Display.setVSyncEnabled(true);
		}
		catch (LWJGLException e) {
			throw new RuntimeException(e);
		}
	}
	private void initOpenGL() {
		GL11.glClearColor(0.0f, 0.0f, 0.0f, 0.0f);

       	GL11.glViewport(0,0,SCREEN_WIDTH,SCREEN_HEIGHT);
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, SCREEN_WIDTH, SCREEN_HEIGHT, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);

		GL11.glDisable(GL11.GL_BLEND);
		GL11.glDisable(GL11.GL_DITHER);
		GL11.glDisable(GL11.GL_FOG);
		GL11.glDisable(GL11.GL_LIGHTING);
		GL11.glDisable(GL11.GL_TEXTURE_1D);
		GL11.glDisable(GL11.GL_TEXTURE_2D);
		GL11.glShadeModel(GL11.GL_FLAT);
	}

	static public String byteToHex(int x) {
		String s = Integer.toHexString(x & 255);
		if (s.length()<2) s = "0"+s;
		return s;
	}
	
	private int makeMask(int x) {
		int a = -1;
		a <<= x;
		return ~a;
	}
	
	private double cutOut(int value, int bitPosition, int bitWidth) {
		int mask = makeMask(bitWidth); 
		value >>>= bitPosition;
		value &= mask;
		
		double d = value;
		d /= mask;
		return d;
	}

	private int cutOutB(int value, int bitPosition, int bitWidth) {
		int mask = makeMask(bitWidth); 
		value >>>= bitPosition;
		value &= mask;
		
		int d = value*255;
		d /= mask;
		return d;
	}
	
	int[] generate(int bits) {
		int size = 1<<bits;
		int mask = size-1;
		int[] answer = new int[size];
		for (int v=0; v<size; v++) {
			int x = v * 255 * 0x100;
			x /= mask;
			answer[v] = x;
		}
		return answer;
	}

	private void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		
		int redBits = GL11.glGetInteger(GL11.GL_RED_BITS);
		int greenBits = GL11.glGetInteger(GL11.GL_GREEN_BITS);
		int blueBits = GL11.glGetInteger(GL11.GL_BLUE_BITS);

		int[] a = generate(2);
		for (int i=0; i<a.length; i++) {
			System.out.println(String.format("%3d %04x", i, a[i]));
		}
		
		int[] a2 = generate(3);
		for (int i=0; i<a2.length; i++) {
			System.out.println(String.format("%3d %04x", i, a2[i]));
		}
		
		
		
//		System.out.println(tc);
		int colorBits = redBits + greenBits + blueBits;
		int numPrims = 1<<colorBits;
		int ww = 1<<(colorBits/2);
		for (int indx=0; indx<numPrims; indx++) {
//			double r = cutOut(indx, greenBits+blueBits, redBits);
//			double g = cutOut(indx, blueBits, greenBits);
//			double b = cutOut(indx, 0, blueBits);
//			GL11.glColor3d(r, g, b);
			
			int r = cutOutB(indx, greenBits+blueBits, redBits);
			int g = cutOutB(indx, blueBits, greenBits);
			int b = cutOutB(indx, 0, blueBits);
			GL11.glColor3ub((byte)r, (byte)g, (byte)b);
			
			
			
			int x = indx % ww;
			int y = indx / ww;
			

//			System.out.println(Integer.toString(c)+":"+byteToHex(r)+byteToHex(g)+byteToHex(b));
//			r = (byte) 0x80;
//			g = (byte) 0x80;
//			b = (byte) 0x80;
			
//			GL11.glColor3ub(r, g, b);
			
			/*
			 * 
			 * How
			 */
			
			int scale = 1;
			x *= scale;
			y *= scale;
			x += 50;
			y += 50;
			GL11.glRectf(x,y,x+scale,y+scale);
//			GL11.glBegin(GL11.GL_QUADS);
//			GL11.glVertex2f(x, y);
//			GL11.glVertex2f(x + scale, y);
//			GL11.glVertex2f(x + scale, y + scale);
//			GL11.glVertex2f(x, y + scale);
//			GL11.glEnd();
		}
	
	}

	private void startTheExample() {
		initLwjglDisplay();
		initOpenGL();
		while (true) {
			render();
			Display.update();
			Display.sync(10);
			if (Display.isCloseRequested()) {
				Display.destroy();
				break;
			}
		}
	}

	public static void main(String[] argv) {
		ColorBox cb = new ColorBox();
		cb.startTheExample();
	}
}