package com.nney.tt;

import org.lwjgl.opengl.GL11;

public class PrerenderedText {
	private final int width;
	private final int id;

	public PrerenderedText(int width, int id) {
		this.width = width;
		this.id = id;
	}

	int getWidth() {
		return width;
	}
	
	void draw(int x, int y) {
		GL11.glPushMatrix();
		GL11.glTranslatef(x, y, 0);
		GL11.glCallList(id);
		GL11.glPopMatrix();
	}
	
	void dispose() {
		GL11.glDeleteLists(id, 1);
	}
}
