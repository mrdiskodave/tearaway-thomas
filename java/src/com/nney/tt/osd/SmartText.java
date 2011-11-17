package com.nney.tt.osd;

import com.nney.tt.DisposableField;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.PrerenderedText;

/**
 * Text that can be changed.
 */
class SmartText extends AbstractText {
	private DisposableField<PrerenderedText> content = new DisposableField<PrerenderedText>();

	private String contentDescription;

	private final Font font;

	public SmartText(Font font) {
		this.font = font;
	}

	public SmartText(Font font, int col, int kern, String string) {
		this(font);
		set(col, kern, string);
	}

	void set(int col, int kern, String next) {
		String nextDescription = String.format("%x-%x-%s", col, kern, next);
		if (content.empty() || !nextDescription.equals(contentDescription)) {
			content.set(font.preRender(col, kern, next));
			contentDescription = nextDescription;
		}
	}

	@Override
	public void draw(int x, int y) {
		content.get().draw(x, y);
	}

	@Override
	public int width() {
		return content.get().width();
	}

	@Override
	public int height() {
		return content.get().height();
	}

	@Override
	public void dispose() {
		content.dispose();
	}
}
