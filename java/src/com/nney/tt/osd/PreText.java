package com.nney.tt.osd;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.PrerenderedText;

/**
 * Text that never changes and that needs a call to {@link #render()} before
 * it can be used.
 */
public class PreText extends AbstractText {
	private final Font font;
	private final int col;
	private final int kern;
	private final String text;
	private PrerenderedText content;

	public PreText(Font font, int col, int kern, String text) {
		this.font = font;
		this.col = col;
		this.kern = kern;
		this.text = text;
	}

	@Override
	public int width() {
		mustHaveContent();
		return content.width();
	}

	@Override
	public int height() {
		mustHaveContent();
		return content.height();
	}

	@Override
	public void draw(int x, int y) {
		mustHaveContent();
		content.draw(x, y);
	}

	@Override
	public void dispose() {
		mustHaveContent();
		content.dispose();
	}

	private void mustHaveContent() {
		if (content==null) {
			throw new IllegalStateException("Needed a call to render() first");
		}
	}
	
	public void render() {
		System.out.println("RENDERING:"+text+"k"+kern);
		content = font.preRender(col, kern, text);
	}
}
