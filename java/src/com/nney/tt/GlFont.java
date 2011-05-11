package com.nney.tt;

import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;

public class GlFont extends MyFont {
	public GlFont(byte[] data, int miniW, int miniH, boolean proportional, String characters) {
		super(data, miniW, miniH, proportional, characters);
	}

	private GlTexture texture;
	
	@Override
	public void dispose() {
		texture.dispose();
	}

	@Override
	protected void renderContent() {
		this.texture = new GlTexture(content, mono);
	}

	@Override
	protected void stopDrawing() {
		GL11.glEnd();
		GlTools.configureFor2dBobs();
	}

	@Override
	protected void drawChar(int dx, int dy, Bounds z) {
		texture.drawQuad(dx, dy, z.width, z.height, z.left, z.top, z.width, z.height);
	}

	@Override
	protected void startDrawing(int fg) {
		GlTools.configureForFont(mono, fg);
		texture.bindTexture();
		GL11.glBegin(GL11.GL_QUADS);
	}
	
	@Override
	public PrerenderedText preDraw(int fg, int kern, String text) {
		int id = GL11.glGenLists(1);
		GL11.glNewList(id, GL11.GL_COMPILE);
		int width = draw(0, 0, fg, kern, text)-kern;
		GL11.glEndList();
		return new GlPrerenderedText(width, id);
	}
}
