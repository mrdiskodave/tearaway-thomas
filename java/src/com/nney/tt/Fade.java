package com.nney.tt;

import com.nney.tt.gfx.GraphicsContext;
import com.nney.utils.Math2;

/**
 * Hide the screen contents by fading it to black.
 */
public class Fade extends CurtainImpl {
	private static final int PADDING = 0x100;
	private final GraphicsContext gc;
	private final int darkest;
	private final int rate;
	
	public Fade(GraphicsContext gc, int darkest, float time) {
		this.gc = gc;
		this.darkest = darkest*PADDING;
		this.rate = (int) ((this.darkest)/(Const.FPS*time));
		current(OPEN);
		target(OPEN);
	}
	
	public Fade(GraphicsContext gc) {
		this(gc, 0, 1);
	}
	
	@Override
	protected int stateToValue(int state) {
		return Math2.fracMult(darkest, state, CLOSED);
	}
	
	@Override
	public void move() {
		currentValue = Math2.closer(currentValue, targetValue, rate);
	}
	
	@Override
	public void draw() {
		int c = currentValue>>8;
		if (c!=0) {
			gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), c<<24);
		}
	}
}
