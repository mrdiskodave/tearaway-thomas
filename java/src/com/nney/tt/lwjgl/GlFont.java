package com.nney.tt.lwjgl;

import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.PartialFontImpl;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.gfx.SimpleImage;

//
// font2.png is all 255 / 136
// e.g. red multiples out as 255,0,0 / 136,0,0
//
// in the original red was an exception and
// was rendered as 255,51,51 / 136,17,17
//
// we can't do this with our current rendering system so
// red text looks harsher than it did before
//

public class GlFont extends PartialFontImpl {
	public GlFont(byte[] data, int miniW, int miniH, boolean proportional, String characters) {
		super(data, miniW, miniH, proportional, characters);
	}

	private GlTexture texture;

	@Override
	public void dispose() {
		if (texture != null) texture.dispose();
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
	public PrerenderedText preRender(int fg, int kern, String text) {

		if (Main.GL_EXT_framebuffer_object) {
			int w = computeWidth(kern, text);
			int h = charHeight();
//			System.out.println("Pre-rendering into FBO "+w+","+h);
			
//			SimpleImage si = SimpleImage.createEmpty(w, h);
//			si.fill(0xffff00ff);
//			GlTexture t = new GlTexture(si);
			
			GlTexture t = new GlTexture(w, h);
			GlFrameBufferObject fbo = new GlFrameBufferObject(t);
			draw(0, 0, fg, kern, text);
			fbo.dispose();
			return t;
		}
		
		
		int id = GL11.glGenLists(1);
		GL11.glNewList(id, GL11.GL_COMPILE);
		int width = draw(0, 0, fg, kern, text) - kern;
		GL11.glEndList();
		return new GlPrerenderedText(width, miniH, id);
	}

}
