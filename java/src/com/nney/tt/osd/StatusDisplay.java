package com.nney.tt.osd;

import com.nney.tt.geom.Coord;
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
	private final AbstractText timeUpText;

	final private MultiDisposable md = new MultiDisposable();
	private StaticText pressJumpText;

	public StatusDisplay(GraphicsContext gc, Font font) {
		this.gc = gc;

		exitOpenText = new StaticText(font, COL_GOOD, 0, "exit open");
		hurryUpText = new StaticText(font, COL_BAD, 0, "hurry up");
		pausedText = new StaticText(font, 0xff00ffff, 0, "paused");
		lifeLostText = new StaticText(font, COL_BAD, 0, "life lost");
		timeUpText = new StaticText(font, COL_BAD, 0, "time up");
		pressJumpText = new StaticText(font, 0xffffff00, 0, "press jump");

		md.addMany(exitOpenText, hurryUpText, pausedText, lifeLostText, timeUpText, pressJumpText);
	}

	public void drawExitOpen() {
		drawHigh(exitOpenText);
	}

	public void drawHurryUp() {
		drawLow(hurryUpText);
	}

	public void drawTimeUp() {
		drawLow(timeUpText);
	}

	public void drawPaused() {
		drawLow(pausedText);
	}

	public void drawLifeLost(Coord c) {
		// where is it?

		// make sure it hasn't gone off screen to the left or right
		// (which it will if the player is against the edge)
		int w = lifeLostText.width();
		int nx = c.x - w / 2;
		int minx = 1;
		int maxx = gc.screenWidth() - minx - w;
		nx = Math2.limit(minx, maxx, nx);

		// same for Y
		// as the player can die by falling off the bottom of the map
		int h = lifeLostText.height();
		int ny = c.y;
		int miny = 1;
		int maxy = gc.screenHeight() - miny - h;
		ny = Math2.limit(miny, maxy, ny);

		// draw it!
		lifeLostText.draw(nx, c.y);
	}

	private void drawLow(AbstractText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, Math2.percent(gc.screenHeight(), 80));
	}

	private void drawHigh(AbstractText t) {
		int midX = gc.screenWidth() / 2;
		t.centredDraw(midX, Math2.percent(gc.screenHeight(), 35));
	}

	@Override
	public void close() {
		md.close();
	}

}
