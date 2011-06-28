package com.nney.tt;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.PrerenderedText;

public class HeadUpDisplay {
	private static final int COL_HEADING = 0xffffffff;

	private static final int COL_NORMAL = 0xffffff00;
	private static final int COL_GEM_HAPPY = 0xff00ff00;

	private static final int COL_EXIT_OPEN = 0xff00ff00;
	private static final int COL_HURRY_UP = 0xffff0000;

	
	private static final int GAP = 3;

	private final GraphicsContext gc;

	private final Font font;
	
	class SmartText {
		private PrerenderedText content;

		private String slast = "";

		public SmartText() {
		}

		public SmartText(int i, String string) {
			set(i, string);
		}

		void set(int col, String next) {
			String snext = String.format("%x-%s", col, next);
			if (!slast.equals(snext)) {
				content = font.preDraw(col, 0, next);
				slast = snext;
			}
		}

		void draw(int x, int y) {
			content.draw(x-halfWidth(), y);
		}
		
		int halfWidth() {
			return content.width() / 2;
		}

		int height() {
			return content.height();
		}

	}

	class ReadOut {

		private SmartText headingText = new SmartText();
		private SmartText contentText = new SmartText();

		private final String heading;

		ReadOut(String heading) {
			this.heading = heading;
		}

		void set(int col, String content) {
			headingText.set(COL_HEADING, heading);
			contentText.set(col, content);
		}
		
		void draw(int x, int y) {
			headingText.draw(x, y);
			contentText.draw(x, y + headingText.height() + GAP);
		}
		
		
		int halfWidth() {
			return headingText.halfWidth();
		}

		int height() {
			return contentText.height()*2+GAP;
		}
	}

	private ReadOut scoreReadOut;
	private ReadOut gemsReadOut;
	private ReadOut timeReadOut;

	private SmartText exitOpen;

	private SmartText hurryUp;

	public HeadUpDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;
		this.font = font;
		scoreReadOut = new ReadOut("score");
		gemsReadOut = new ReadOut("gems");
		timeReadOut = new ReadOut("time");
		
		exitOpen = new SmartText(COL_EXIT_OPEN, "exit open");
		hurryUp = new SmartText(COL_HURRY_UP, "hurry up");
		
	}

	public void update(int score, int time, int gems, boolean isExitOpen) {
		int border = 6;

		scoreReadOut.set(COL_NORMAL, String.format("%08d", score));

		gemsReadOut.set(isExitOpen ? COL_GEM_HAPPY : COL_NORMAL, String.format("%02d", gems));
		timeReadOut.set(COL_NORMAL, String.format("%02d", time));

		scoreReadOut.draw(gc.screenWidth() / 2, border);

		int bottomY = gc.screenHeight() - gemsReadOut.height() - border;
		int middleFromEdgeX = border + gemsReadOut.halfWidth();

		gemsReadOut.draw(middleFromEdgeX, bottomY);
		timeReadOut.draw(gc.screenWidth() - middleFromEdgeX, bottomY);
		
		if (isExitOpen) {
			exitOpen.draw(gc.screenWidth() / 2, gc.screenHeight()*7/20);
		}
	}

}
