package com.nney.tt.osd;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.utils.Math2;

public class StatusDisplay implements Disposable {
	private static final int COL_BAD = 0xffff0000;
	private static final int COL_GOOD = 0xff00ff00;

	private final GraphicsContext gc;
	private final AbstractText exitOpenText;
	private final AbstractText hurryUpText;
	private final AbstractText pausedText;
	private final AbstractText lifeLostText;

	final private MultiDisposable md = new MultiDisposable();

	public StatusDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;

		exitOpenText = new StaticText(font, COL_GOOD, 0, "exit open");
		hurryUpText = new StaticText(font, COL_BAD, 0, "hurry up");
		pausedText = new StaticText(font, 0xff00ffff, 0, "paused");
		lifeLostText = new StaticText(font, COL_BAD, 0, "life lost");
		
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

	private void drawLow(AbstractText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, Math2.fracMult(gc.screenHeight(), 16, 20));
	}

	private void drawHigh(AbstractText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, Math2.fracMult(gc.screenHeight(), 7, 20));
	}

	@Override
	public void dispose() {
		md.dispose();
	}

}
