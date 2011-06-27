package com.nney.tt;

import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.PrerenderedText;

public class HeadUpDisplay {
	private int oldScore = -1;

	private PrerenderedText scoreHeadingText;

	private PrerenderedText scoreText;

	private final GraphicsContext gc;

	private final Font font;
	
	public HeadUpDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;
		this.font = font;
	}

	public void update(int score) {
		if (score != oldScore) {
			scoreHeadingText = font.preDraw(0xffffff00, 0, "score");
			scoreText = font.preDraw(0xffffffff, 0, String.format("%08d", score));
		}
		scoreHeadingText.draw((gc.screenWidth() - scoreHeadingText.width()) / 2, 6);
		scoreText.draw((gc.screenWidth() - scoreText.width()) / 2, 6 + 14);
	}

}
