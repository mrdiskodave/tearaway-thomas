package com.nney.tt.osd;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.PrerenderedText;

class SmartText extends AbstractText {
	private PrerenderedText content;

	private String slast = "";

	private final Font font;

	public SmartText(Font font) {
		this.font = font;
	}

	public SmartText(Font font, int col, int kern, String string) {
		this(font);
		set(col, kern, string);
	}

	void set(int col, int kern, String next) {
		String snext = String.format("%x-%x-%s", col, kern, next);
		if (!slast.equals(snext)) {
			dispose();
			content = font.preRender(col, kern, next);
			slast = snext;
		}
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
	public void dispose() {
		if (content != null) {
			content.dispose();
			content = null;
		}
	}

}
