package com.nney.tt.osd;

import com.nney.tt.Const;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.tt.sprites.Sprite;

public class HeadUpDisplay implements Disposable {
	private static final int COL_HEADING = 0xffffffff;

	private static final int COL_NORMAL = 0xffffff00;
	private static final int COL_BAD = 0xffff0000;
	private static final int COL_GOOD = 0xff00ff00;

	private static final int COL_GEM_HAPPY = COL_GOOD;

	// private static final int COL_EXIT_OPEN = COL_GOOD;

	// private static final int COL_HURRY_UP = COL_BAD;

	private static final int GAP = 3;

	private final GraphicsContext gc;

	class ReadOut implements Disposable {
		private final StaticText headingText;
		private SmartText contentText;

		ReadOut(Font font, String heading) {
			headingText = new StaticText(font, COL_HEADING, 0, heading);
			contentText = new SmartText(font);
		}

		void set(int col, String content) {
			contentText.set(col, 0, content);
		}

		void centredDraw(int x, int y) {
			headingText.centredDraw(x, y);
			contentText.centredDraw(x, y + GAP + headingText.height());
		}

		int width() {
			return Math.max(headingText.width(), contentText.width());
		}

		int height() {
			return contentText.height() * 2 + GAP;
		}

		@Override
		public void close() {
			headingText.close();
			contentText.close();
		}
	}

	private ReadOut scoreReadOut;
	private ReadOut gemsReadOut;
	private ReadOut timeReadOut;

	private SmartText livesText;

	private RowComponent livesRow;

	final private MultiDisposable md = new MultiDisposable();

	public HeadUpDisplay(GraphicsContext gc, Font font, Sprite lifeSprite) {
		this.gc = gc;

		scoreReadOut = new ReadOut(font, "score");
		gemsReadOut = new ReadOut(font, "gems");
		timeReadOut = new ReadOut(font, "time");
		livesText = new SmartText(font);
		SmartText xText = new SmartText(font, COL_HEADING, 0, "x");
		md.addMany(scoreReadOut, gemsReadOut, timeReadOut, livesText, xText);

		livesRow = new RowComponent(Justify.CENTRED);
		livesRow.add(new SpriteComponent(lifeSprite));
		livesRow.add(new SpacerComponent(4, 1));
		livesRow.add(xText);
		livesRow.add(new SpacerComponent(4, 1));
		livesRow.add(livesText);
	}

	public void update(int score, int time, boolean showHurryUp, int gems, boolean isExitOpen, int lives) {
		//
		// score/gems/time
		//

		int border = 6;

		int midX = gc.screenWidth() / 2;

		scoreReadOut.set(COL_NORMAL, String.format("%08d", score));

		gemsReadOut.set(isExitOpen ? COL_GEM_HAPPY : COL_NORMAL, String.format("%02d", gems));

		timeReadOut.set(showHurryUp ? COL_BAD : COL_NORMAL, String.format("%02d", time / Const.FPS));

		scoreReadOut.centredDraw(midX, border);

		int bottomY = gc.screenHeight() - gemsReadOut.height() - border;
		int middleFromEdgeX = border + gemsReadOut.width() / 2;

		gemsReadOut.centredDraw(middleFromEdgeX, bottomY);
		timeReadOut.centredDraw(gc.screenWidth() - middleFromEdgeX, bottomY);

		//
		// lives
		//

		livesText.set(COL_HEADING, 0, String.format("%d", lives));
		int livesX = (midX - livesRow.width() / 2);
		int livesY = bottomY + (gemsReadOut.height() - livesRow.height()) / 2;
		livesRow.draw(livesX, livesY);
	}

	@Override
	public void close() {
		md.close();
	}
}
