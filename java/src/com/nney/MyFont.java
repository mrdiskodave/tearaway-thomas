package com.nney;


public class MyFont {
	private int[] widths;
	private final SimpleImage content;
	private final int miniW;
	private final int miniH;
	private final int count;
	private String characters;

	public MyFont(SimpleImage content, int miniW, int miniH, int count) {
		this.content = content;
		this.miniW = miniW;
		this.miniH = miniH;
		this.count = count;
		
		widths = new int[count];
		discoverWidths();
	}

	public void discoverWidths() {
		TemporaryBlockSource tbs = new TemporaryBlockSource(content, miniW, miniH);
		for (int x=0; x<count; x++) {
			SimpleImage glyph = tbs.getBlock(x);
			widths[x] = glyph.getBounds().width;
		}
	}
	
	public void setCharacters(String characters) {
		this.characters = characters;
	}
}
