package com.nney.tt;

import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.GlTexture;
import com.nney.tt.gfx.GlTools;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.TemporaryBlockSource;

public class MyFont {
	private static final int DANGER = 0xffff0101;
	final private SimpleImage content;
	final private String characters;
	final private Bounds[] boxes;
	final private GlTexture texture;
	private boolean mono;

	public static String characterRangeHelper(int begin, int end) {
		StringBuilder sb = new StringBuilder();
		for (int x = begin; x < end; x++) {
			sb.append((char) x);
		}
		return sb.toString();
	}

	public MyFont(byte[] data, int miniW, int miniH, boolean proportional,
			String characters) {
		this.content = new SimpleImage(data);
		TemporaryBlockSource bs = new TemporaryBlockSource(content, miniW, miniH);
		int count = bs.getBlockCount();
		boxes = new Bounds[count];
		this.characters = characters;
		assert characters.length() == boxes.length : "difference "+characters.length()+" "+boxes.length;

		for (int x = 0; x < count; x++) {
			Bounds box = bs.getBlockBounds(x);
			if (proportional) {
				int realWidth = shaveRedOffTheRight(bs.getBlock(x));
				box = new Bounds(box.left, box.top, realWidth, box.height);
			}
			boxes[x] = box;
		}

		int[] palette = content.collectPalette();
		mono = palette.length==2;
		this.texture = new GlTexture(content, mono);
	}

	private int shaveRedOffTheRight(SimpleImage glyph) {
		int glyphWidth = glyph.getWidth();
		for (;;) {
			SimpleImage stripView = glyph.view(glyphWidth-1, 0, 1, glyph.getHeight());
			if (!stripView.isEntirely(DANGER)) break;
			stripView.fill(0);
			glyphWidth--;
		}
		return glyphWidth;
	}

	public int draw(int dx, int dy, int fg, int kern, String text) {
		// configure the texture system
		GlTools.configureForFont(mono, fg);

		texture.bindTexture();
		GL11.glBegin(GL11.GL_QUADS);
		for (int x = 0; x < text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p >= 0) {
				Bounds z = boxes[p];
				texture.drawQuad(dx, dy, z.width, z.height, z.left, z.top, z.width, z.height);
				dx += z.width + kern;
			}
		}
		GL11.glEnd();
		
		// put it back in its agreed-default state 
		GlTools.configureFor2dBobs();
		
		return dx;
	}
	
	PrerenderedText preDraw(int fg, int kern, String text) {
		int id = GL11.glGenLists(1);
		GL11.glNewList(id, GL11.GL_COMPILE);
		int width = draw(0, 0, fg, kern, text)-kern;
		GL11.glEndList();
		return new PrerenderedText(width, id);
	}

	public int computeWidth(int kern, String text) {
		int dx = 0;
		for (int x = 0; x < text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p >= 0) {
				Bounds z = boxes[p];
				dx += z.width + kern;
			}
		}
		return dx;
	}

	
	public void dispose() {
		texture.dispose();
	}
}
