package com.nney.tt.osd;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.PrerenderedText;

/**
 * Text that never changes.
 */
class StaticText extends AbstractText {
	final private PrerenderedText content;

	public StaticText(Font font, int col, int kern, String string) {
		content = font.preRender(col, kern, string);
	}

	@Override
	public void draw(int x, int y) {
		content.draw(x, y);
	}

	@Override
	public int width() {
		return content.width();
	}

	@Override
	public int height() {
		return content.height();
	}

	@Override
	public void close() {
		content.close();
	}
}
