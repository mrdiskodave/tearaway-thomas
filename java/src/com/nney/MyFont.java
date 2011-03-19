package com.nney;

import org.lwjgl.opengl.GL11;

public class MyFont {
	final private SimpleImage content;
	final private String characters;
	final private Bounds[] boxes;
	final private Texture texture;
	private int texMode;

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
		int glFormat;
		if (palette.length==2) {
			System.out.println("Alpha font");
			// we can save 75% of font storage space this way
			// and maybe they also draw faster as there is 75% less data moving about
			glFormat = GL11.GL_ALPHA;
			texMode = GL11.GL_REPLACE; 
		}
		else {
			System.out.println("Color font");
			glFormat = GL11.GL_RGBA8;
			texMode = GL11.GL_MODULATE; 
			// GL_MODULATE simply takes the color and alpha data from the texture and multiplies it with the color data from glColor and/or the lighting system.
			// says http://www.nullterminator.net/gltexture.html
		}
		this.texture = new Texture(content, glFormat);

	}

	private int shaveRedOffTheRight(SimpleImage glyph) {
		int glyphWidth = glyph.getWidth();
		for (;;) {
			SimpleImage stripView = glyph.view(glyphWidth-1, 0, 1, glyph.getHeight());
			if (!stripView.isEntirely(0xffff0101)) break;
			stripView.fill(0);
			glyphWidth--;
		}
		return glyphWidth;
	}

	public void draw(int dx, int dy, int fg, int kern, String text) {
		int r = ( fg >> 2*8 ) & 0xff;
		int g = ( fg >> 8 ) & 0xff;
		int b = ( fg ) & 0xff;
		
		// configure the texture system
		GL11.glEnable(GL11.GL_TEXTURE_2D);
		GL11.glEnable(GL11.GL_BLEND);
		GL11.glBlendFunc(GL11.GL_SRC_ALPHA, GL11.GL_ONE_MINUS_SRC_ALPHA);
		GL11.glColor3ub((byte)r, (byte)g, (byte)b);
		GL11.glTexEnvf(GL11.GL_TEXTURE_ENV, GL11.GL_TEXTURE_ENV_MODE, texMode);
		
		for (int x = 0; x < text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p >= 0) {
				Bounds z = boxes[p];
				texture.draw(dx, dy, z.left, z.top, z.width, z.height);
				dx += z.width + kern;
			}
		}
	}
	
	public void dispose() {
		texture.dispose();
	}
}
