package com.nney;

import org.lwjgl.LWJGLException;
import org.lwjgl.opengl.Display;
import org.lwjgl.opengl.DisplayMode;
import org.lwjgl.opengl.GL11;

public class OriginalTextureExample {
	
	/**
	 * Start the example
	 */
	public void start() {
		initGL(800,600);
		init();
		
		while (true) {
			render();
			
			Display.update();
			Display.sync(100);

			if (Display.isCloseRequested()) {
				Display.destroy();
				System.exit(0);
			}
		}
	}
	
	/**
	 * Initialise the GL display
	 * 
	 * @param width The width of the display
	 * @param height The height of the display
	 */
	private void initGL(int width, int height) {
		try {
			Display.setDisplayMode(new DisplayMode(width,height));
			Display.create();
			Display.setVSyncEnabled(true);
		} catch (LWJGLException e) {
			e.printStackTrace();
			System.exit(0);
		}

//		GL11.glEnable(GL11.GL_TEXTURE_2D);               
        
		GL11.glClearColor(0.0f, 0.0f, 0.0f, 0.0f);          
        
        	// enable alpha blending
//        	GL11.glEnable(GL11.GL_BLEND);
//        	GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);
        
       	GL11.glViewport(0,0,width,height);
		GL11.glMatrixMode(GL11.GL_PROJECTION);
		GL11.glLoadIdentity();
		GL11.glOrtho(0, width, height, 0, 1, -1);
		GL11.glMatrixMode(GL11.GL_MODELVIEW);
	}
	
	/**
	 * Initialise resources
	 */
	public void init() {
	}

	/**
	 * draw a quad with the image on it
	 */
	public void render() {
		GL11.glClear(GL11.GL_COLOR_BUFFER_BIT);
		GL11.glColor3f(1.0f,1.0f,1.0f);
		GL11.glRectf(10,10,100,100);
//
//		//		Color.white.bind();
//		int z = 100;
//		GL11.glBegin(GL11.GL_QUADS);
//			GL11.glTexCoord2f(0,0);
//			GL11.glVertex2f(100,100);
//			GL11.glTexCoord2f(1,0);
//			GL11.glVertex2f(100+z,100);
//			GL11.glTexCoord2f(1,1);
//			GL11.glVertex2f(100+z,100+z);
//			GL11.glTexCoord2f(0,1);
//			GL11.glVertex2f(100,100+z);
//		GL11.glEnd();
	}
	
	/**
	 * Main Class
	 */
	public static void main(String[] argv) {
		OriginalTextureExample textureExample = new OriginalTextureExample();
		textureExample.start();
	}
}