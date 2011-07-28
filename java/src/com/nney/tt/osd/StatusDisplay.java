package com.nney.tt.osd;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.MultiDisposable;

public class StatusDisplay implements Disposable {
	private static final int COL_BAD = 0xffff0000;
	private static final int COL_GOOD = 0xff00ff00;

	private final GraphicsContext gc;
	private final SmartText exitOpenText;
	private final SmartText hurryUpText;
	private final SmartText pausedText;
	private final SmartText lifeLostText;

	final private MultiDisposable md = new MultiDisposable();

	public StatusDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;

		exitOpenText = new SmartText(font, COL_GOOD, 0, "exit open");
		hurryUpText = new SmartText(font, COL_BAD, 0, "hurry up");
		pausedText = new SmartText(font, 0xff00ffff, 0, "paused");
		lifeLostText = new SmartText(font, COL_BAD, 0, "life lost");
		
		md.addMany(exitOpenText, hurryUpText, pausedText, lifeLostText);
	}
	
	public void updateHurryUp(int time) {
		//
		// hurry up
		//
			drawLow(hurryUpText);
	}
	
	public void drawExitOpen() {
		drawHigh(exitOpenText);
	}
	
	public void drawPaused() {
		drawLow(pausedText);
	}
	
	public void drawLifeLost() {
		drawLow(lifeLostText);
	}

	private void drawLow(SmartText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, gc.screenHeight() * 16 / 20);
	}

	private void drawHigh(SmartText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, gc.screenHeight() * 7 / 20);
	}

	@Override
	public void dispose() {
		md.dispose();
	}

}
