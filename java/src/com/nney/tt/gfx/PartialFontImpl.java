package com.nney.tt.gfx;

public abstract class PartialFontImpl implements Font {
	protected static final int ABSENT = 0xffff0101;
	final protected SimpleImage content;
	final protected String characters;
	final protected Bounds[] boxes;
	protected boolean mono;
	private final boolean proportional;
	private final int miniW;
	protected final int miniH;

	@Override
	public int charWidth() {
		return proportional ? -1 : miniW;
	}

	@Override
	public int charHeight() {
		return miniH;
	}

	public PartialFontImpl(byte[] data, int miniW, int miniH, boolean proportional, String characters) {
		this.miniW = miniW;
		this.miniH = miniH;
		this.proportional = proportional;
		this.content = new SimpleImage(data);
		BlockSource bs = new BlockSource(content, miniW, miniH);
		int count = bs.getBlockCount();
		boxes = new Bounds[count];
		this.characters = characters;
		assert characters.length() == boxes.length : "difference " + characters.length() + " " + boxes.length;

		for (int x = 0; x < count; x++) {
			Bounds box = bs.getBlockBounds(x);
			if (proportional) {
				int realWidth = shaveRedOffTheRight(bs.getBlock(x));
				box = new Bounds(box.left, box.top, realWidth, box.height);
			}
			boxes[x] = box;
		}

		int[] palette = content.collectPalette();
		mono = palette.length == 2;
		renderContent();
	}

	private int shaveRedOffTheRight(SimpleImage glyph) {
		int glyphWidth = glyph.width();
		for (;;) {
			SimpleImage stripView = glyph.view(glyphWidth - 1, 0, 1, glyph.height());
			if (!stripView.isEntirely(ABSENT)) break;
			stripView.fill(0);
			glyphWidth--;
		}
		return glyphWidth;
	}

	@Override
	public int draw(int dx, int dy, int fg, int kern, String text) {
		// configure the texture system
		startDrawing(fg);

		for (int x = 0; x < text.length(); x++) {
			char c = text.charAt(x);
			int p = characters.indexOf(c);
			if (p >= 0) {
				Bounds z = boxes[p];
				drawChar(dx, dy, z);
				dx += z.width + kern;
			}
		}

		stopDrawing();

		return dx;
	}

	@Override
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

	@Override
	abstract public void dispose();

	abstract protected void renderContent();

	abstract protected void stopDrawing();

	abstract protected void drawChar(int dx, int dy, Bounds z);

	abstract protected void startDrawing(int fg);

	@Override
	abstract public PrerenderedText preDraw(int fg, int kern, String text);
}
