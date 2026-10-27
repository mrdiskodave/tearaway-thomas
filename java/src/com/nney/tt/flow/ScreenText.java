package com.nney.tt.flow;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.osd.OsdParser;
import com.nney.tt.osd.StatusScreen;

/**
 * A screenful of text in the game's markup (see {@link OsdParser}), centred.
 */
final class ScreenText implements Disposable {
	private final StatusScreen ss;

	ScreenText(GraphicsContext gc, Font font, String markup) {
		ss = new StatusScreen(gc, font);
		new OsdParser(ss).parse(markup);
		ss.done();
		ss.prepare();
	}

	void draw() {
		ss.update();
	}

	@Override
	public void dispose() {
		ss.dispose();
	}
}
