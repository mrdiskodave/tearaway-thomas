package com.nney.tt;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.PrerenderedText;

public class HeadUpDisplay {
	private final GraphicsContext gc;

	private final Font font;

	class ReadOut {
		private static final int GAP = 3;

		private PrerenderedText headingText;

		private PrerenderedText content;

		private String last = "";

		ReadOut(String heading) {
			headingText = font.preDraw(0xffffff00, 0, heading);
		}

		void set(String next) {
			if (!last.equals(next)) {
				content = font.preDraw(0xffffffff, 0, next);
				last = next;
			}
		}

		void draw(int x, int y) {
			headingText.draw(x - halfWidth(), y);
			content.draw(x - content.width() / 2, y + headingText.height() + GAP);
		}

		private int halfWidth() {
			return headingText.width() / 2;
		}

//		int width() {
//			return headingText.width();
//		}

		int height() {
			return headingText.height() * 2 + GAP;
		}
	}

	private ReadOut scoreReadOut;
	private ReadOut gemsReadOut;
	private ReadOut timeReadOut;

	public HeadUpDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;
		this.font = font;
		scoreReadOut = new ReadOut("score");
		gemsReadOut = new ReadOut("gems");
		timeReadOut = new ReadOut("time");
	}

	public void update(int score, int time, int gems) {
		int border = 6;

		scoreReadOut.set(String.format("%08d", score));
		scoreReadOut.draw(gc.screenWidth() / 2, border);

		int bottomY = gc.screenHeight() - gemsReadOut.height() - border;
		int middleFromEdgeX = border + gemsReadOut.halfWidth();

		gemsReadOut.set(String.format("%02d", gems));
		gemsReadOut.draw(middleFromEdgeX, bottomY);

		timeReadOut.set(String.format("%02d", time));
		timeReadOut.draw(gc.screenWidth() - middleFromEdgeX, bottomY);
		
		// TODO: lives?
	}

}
