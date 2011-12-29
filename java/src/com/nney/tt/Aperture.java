package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.utils.Math2;

/**
 * Hide the screen contents with an aperture that closes around the screen from
 * the outside in.
 */
public class Aperture extends CurtainImpl {
	private final GraphicsContext gc;

	private Coord centre;

	/**
	 * How big does the Aperture need to get before you cannot see it?
	 */
	private int maxRadius;

	private int rate;

	private long squareDistance(Coord a, Coord b) {
		int xd = a.x - b.x;
		int yd = a.y - b.y;
		return xd * xd + yd * yd;
	}

	public Aperture(GraphicsContext gc) {
		this.gc = gc;
		setCentre(new Coord(gc.screenWidth() / 2, gc.screenHeight() / 2));
		current(OPEN);
		target(OPEN);
		rate = 2;
	}

	@Override
	public void move() {
		currentValue = Math.min(currentValue, maxRadius);
		currentValue = Math2.closer(currentValue, targetValue, rate);
	}

	public void setCentre(Coord centre) {
		this.centre = centre.copy();

		int safetyMargin = 3;
		int loX = -safetyMargin;
		int hiX = gc.screenWidth() + safetyMargin;
		int loY = -safetyMargin;
		int hiY = gc.screenHeight() + safetyMargin;

		long d1 = squareDistance(centre, new Coord(loX, loY));
		long d2 = squareDistance(centre, new Coord(hiX, loY));
		long d3 = squareDistance(centre, new Coord(loX, hiY));
		long d4 = squareDistance(centre, new Coord(hiX, hiY));
		long largestSquareDistanceToEdge = Math.max(d1, Math.max(d2, Math.max(d3, d4)));

		maxRadius = (int) Math.sqrt(largestSquareDistanceToEdge);
		currentValue = maxRadius;
	}

	@Override
	public void draw() {
		if (currentValue < maxRadius) {
			if (currentValue == 0) {
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xff000000);
			}
			else {
				gc.aperture(currentValue, centre.x, centre.y, 0xff000000);
			}
		}
	}

	@Override
	protected int stateToValue(int state) {
		state = CLOSED - state;
		state = Math2.fracMult(state, maxRadius, CLOSED);
		return state;
	}

	@Override
	protected int valueToState(int value) {
		value = Math2.fracMult(value, CLOSED, maxRadius);
		value = CLOSED - value;
		return value;
	}

	public void setRate(int pixelPerFrame) {
		rate = pixelPerFrame;
	}
}
