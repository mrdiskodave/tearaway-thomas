package com.nney;


public class MyFont {
	private int[] widths;
	private SimpleImage content;
	private final int miniW;
	private final int miniH;
	private String characters;
	private TemporaryBlockSource bs;
	private int count;
	private Texture tex;

	public MyFont(SimpleImage content0, int miniW, int miniH) {
		this.content = content0;
		this.miniW = miniW;
		this.miniH = miniH;
		this.bs = new TemporaryBlockSource(content, miniW, miniH);
		this.count = bs.getBlockCount();
		widths = new int[count];
		
//		content = generate(0xff0000ff, 0xffff00ff);
		
		this.tex = new Texture(content);
	}
	
	public void draw(int dx, int dy, String text) {
		for (int x=0; x<text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p>0) {
				Bounds z = bs.getBlockBounds(p);
				tex.draw(dx, dy, z.left, z.top, z.width, z.height);
				dx += widths[p];
				dx ++;
			}
		}
	}

	public void discoverWidths() {
		for (int x=0; x<count; x++) {
			widths[x] = discoverGlyphWidth(x);
		}
	}

	private int discoverGlyphWidth(int x) {
		SimpleImage glyph = bs.getBlock(x);
		Bounds box = glyph.getBounds();
		return box.left+box.width;
	}
	
	public void setCharacters(String characters) {
		this.characters = characters;
		assert characters.length()==widths.length;
	}
	
	public SimpleImage generate(final int fg, final int bg) {
		SimpleImage.ChangePixel c = new SimpleImage.ChangePixel() {
			@Override
			public int change(int c) {
				if (c<0) {
					return c&fg;
				}
				return bg;
			}
		};
		SimpleImage answer = content.copy();
		answer.transform(c);
		return answer;
	}
}
