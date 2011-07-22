package com.nney.tt;

import com.nney.tt.gfx.GraphicsContext;
import com.nney.utils.Math2;

/**
 * Hide the screen contents by fading it to black.
 */
public class Fade implements Curtain {
	private final GraphicsContext gc;
	private int currentValue;
	private int targetState;
	private int targetValue;

	public Fade(GraphicsContext gc) {
		this.gc = gc;
		current(OPEN);
		target(OPEN);
	}

	@Override
	public void current(int state) {
		currentValue = stateToOpacity(state);
	}

	private int stateToOpacity(int state) {
		if (state==OPEN) return 0;
		return 0xffff;
	}

	@Override
	public void target(int state) {
		targetValue = stateToOpacity(state);
		targetState = state;
	}

	@Override
	public int target() {
		return targetState;
	}

	@Override
	public boolean isDone() {
		return currentValue==targetValue;
	}
	
	@Override
	public void update() {
		currentValue = Math2.closer(currentValue, targetValue, 0xffff/(Const.FPS));
	}
	
	@Override
	public void draw() {
		int c = currentValue>>8;
		if (c!=0) {
			gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), c<<24);
		}
	}
}
