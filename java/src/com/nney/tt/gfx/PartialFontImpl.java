package com.nney.tt.gfx;

import java.util.Set;

public abstract class PartialFontImpl implements Font {
	private static final int ABSENT = 0xffff0101;

	final protected String characters;
	final protected Bounds[] boxes;
	private final boolean proportional;
	private final int miniW;
	protected final int miniH;
	protected final int scaleDown;
	private final int missingChar;
	protected final boolean mono;

	@Override
	public int charWidth() {
		return proportional ? -1 : miniW / scaleDown;
	}

	@Override
	public int charHeight() {
		return miniH / scaleDown;
	}

	public PartialFontImpl(RawFont rf) {
		this.scaleDown = rf.scaleDown;
		this.miniW = rf.miniW;
		this.miniH = rf.miniH;
		this.proportional = rf.proportional;
		SimpleImage content = new SimpleImage(rf.data);
		BlockSource bs = new BlockSource(content, miniW, miniH);
		int count = bs.getBlockCount();
		while (count != 0 && bs.isEntirely(count - 1, ABSENT)) {
			count--;
		}

		boxes = new Bounds[count];

		this.characters = rf.characters;
		this.missingChar = rf.characters.indexOf(rf.missingChar);
		assert missingChar >= 0 : "Missing char is, itself, missing!";

		assert characters.length() == count : "difference " + characters.length() + " " + count;

		for (int x = 0; x < count; x++) {
			Bounds box = bs.getBlockBounds(x);
			if (proportional) {
				int realWidth = shaveRedOffTheRight(bs.getBlock(x));
				box = new Bounds(box.left, box.top, realWidth, box.height);
			}
			boxes[x] = box;
		}

		Set<Integer> palette = content.collectPalette();
		palette.remove(ABSENT);
		mono = palette.size() == 2;
		System.out.println("MONO is " + mono);
		renderContent(content);
	}

	private int shaveRedOffTheRight(SimpleImage glyph) {
		int glyphWidth = glyph.width();
		for (;;) {
			SimpleImage stripView = glyph.view(glyphWidth - 1, 0, 1, glyph.height());
			if (!stripView.isEntirely(ABSENT)) break;
			glyphWidth--;
		}
		return glyphWidth;
	}

	private int map(char c) {
		int p = characters.indexOf(c);
		if (p >= 0) return p;
		return missingChar;
	}

	@Override
	public int draw(int dx, int dy, int fg, int kern, String text) {
		// configure the texture system
		startDrawing(fg);

		for (int x = 0; x < text.length(); x++) {
			int p = map(text.charAt(x));
			Bounds z = boxes[p];
			drawChar(dx, dy, z);
			dx += (z.width / scaleDown) + kern;
		}

		stopDrawing();

		return dx;
	}

	@Override
	public int computeWidth(int kern, String text) {
		int dx = 0;
		for (int x = 0; x < text.length(); x++) {
			int p = map(text.charAt(x));
			if (x != 0) dx += kern;
			dx += boxes[p].width / scaleDown;
		}
		return dx;
	}

	abstract protected void renderContent(SimpleImage content);

	abstract protected void startDrawing(int fg);

	abstract protected void drawChar(int dx, int dy, Bounds z);

	abstract protected void stopDrawing();
}
