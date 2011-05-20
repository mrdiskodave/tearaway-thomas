package com.nney.tt.gfx;

public interface Font {
	/**
	 * How wide are all the characters in this font.
	 * 
	 * @return The width in pixels or <code>-1</code> if they have different
	 *         widths (i.e. if the font is proportional).
	 */
	int charWidth();

	/**
	 * How high are all the characters in this font.
	 * 
	 * @return The height in pixels.
	 */
	int charHeight();

	int draw(int dx, int dy, int fg, int kern, String text);

	int computeWidth(int kern, String text);

	PrerenderedText preDraw(int fg, int kern, String text);

	/**
	 * Release any resources associated with this object.
	 */
	void dispose();
}