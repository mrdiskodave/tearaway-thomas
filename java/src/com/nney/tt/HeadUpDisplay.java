package com.nney.tt;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.PrerenderedText;
import com.nney.tt.sprites.Sprite;

public class HeadUpDisplay {
	private static final int COL_HEADING = 0xffffffff;

	private static final int COL_NORMAL = 0xffffff00;
	private static final int COL_BAD = 0xffff0000;
	private static final int COL_GOOD = 0xff00ff00;

	private static final int COL_GEM_HAPPY = COL_GOOD;

	private static final int COL_EXIT_OPEN = COL_GOOD;

	private static final int COL_HURRY_UP = COL_BAD;

	private static final int GAP = 3;

	private final GraphicsContext gc;

	private final Font font;

	class SmartText {
		private PrerenderedText content;

		private String slast = "";

		public SmartText() {
		}

		public SmartText(int col, String string) {
			set(col, string);
		}

		void set(int col, String next) {
			String snext = String.format("%x-%s", col, next);
			if (!slast.equals(snext)) {
				content = font.preDraw(col, 0, next);
				slast = snext;
			}
		}

		void centredDraw(int x, int y) {
			draw(x - width() / 2, y);
		}

		void draw(int x, int y) {
			content.draw(x, y);
		}

		int width() {
			return content.width();
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

		void centredDraw(int x, int y) {
			headingText.centredDraw(x, y);
			contentText.centredDraw(x, y + headingText.height() + GAP);
		}

		int width() {
			return headingText.width();
		}

		int height() {
			return contentText.height() * 2 + GAP;
		}
	}

	private ReadOut scoreReadOut;
	private ReadOut gemsReadOut;
	private ReadOut timeReadOut;

	private SmartText exitOpen;

	private SmartText hurryUp;
	private SmartText livesText;

	private final Sprite lifeSprite;

	public HeadUpDisplay(GraphicsContext gc, Font font, Sprite lifeSprite) {
		this.gc = gc;
		this.font = font;
		this.lifeSprite = lifeSprite;
		scoreReadOut = new ReadOut("score");
		gemsReadOut = new ReadOut("gems");
		timeReadOut = new ReadOut("time");

		livesText = new SmartText();
		exitOpen = new SmartText(COL_EXIT_OPEN, "exit open");
		hurryUp = new SmartText(COL_HURRY_UP, "hurry up");

	}

	public void update(int score, int time, int gems, boolean isExitOpen, int lives) {
		//
		// score/gems/time
		//
		
		int border = 6;

		int midX = gc.screenWidth() / 2;

		scoreReadOut.set(COL_NORMAL, String.format("%08d", score));

		gemsReadOut.set(isExitOpen ? COL_GEM_HAPPY : COL_NORMAL, String.format("%02d", gems));

		boolean hurryUp2 = time < 6 * Const.FPS;
		timeReadOut.set(hurryUp2 ? COL_BAD : COL_NORMAL, String.format("%02d", time / Const.FPS));

		scoreReadOut.centredDraw(midX, border);

		int bottomY = gc.screenHeight() - gemsReadOut.height() - border;
		int middleFromEdgeX = border + gemsReadOut.width() / 2;

		gemsReadOut.centredDraw(middleFromEdgeX, bottomY);
		timeReadOut.centredDraw(gc.screenWidth() - middleFromEdgeX, bottomY);

		
		//
		// exit open
		//
		
		if (isExitOpen) {
			exitOpen.centredDraw(midX, gc.screenHeight() * 7 / 20);
		}

		//
		// hurry up
		//
		
		int mod = 20;

		if (hurryUp2 && (time % mod) < (mod / 2)) {
			hurryUp.centredDraw(midX, gc.screenHeight() * 16 / 20);
		}

		//
		// lives
		//
		
		livesText.set(COL_HEADING, String.format("x%d", lives));

		int livesDisplayHeight = Math.max(livesText.height(), lifeSprite.h);
		int livesDisplayWidth = lifeSprite.w + livesText.width();

		int livesX = (midX - livesDisplayWidth / 2);
		int livesY = bottomY + (gemsReadOut.height() - livesDisplayHeight) / 2;

		int diff = lifeSprite.h - livesText.height();
		int textSticksOutBy = Math.max(0, diff);
		int spriteSticksOutBy = Math.max(0, -diff);

		lifeSprite.draw(livesX + lifeSprite.handleX, livesY + lifeSprite.handleY + (spriteSticksOutBy / 2), false);
		livesX += lifeSprite.w;
		livesText.draw(livesX, livesY + (textSticksOutBy / 2));
	}

}
