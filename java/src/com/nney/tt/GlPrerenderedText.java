package com.nney.tt;

import org.lwjgl.opengl.GL11;

public class GlPrerenderedText implements PrerenderedText {
	private final int width;
	private final int id;

	public GlPrerenderedText(int width, int id) {
		this.width = width;
		this.id = id;
	}

	@Override
	public int getWidth() {
		return width;
	}
	
	@Override
	public void draw(int x, int y) {
		GL11.glPushMatrix();
		GL11.glTranslatef(x, y, 0);
		GL11.glCallList(id);
		GL11.glPopMatrix();
	}
	
	@Override
	public void dispose() {
		GL11.glDeleteLists(id, 1);
	}
}
