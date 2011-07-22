package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.utils.Math2;

/**
 * Hide the screen contents with an aperture that closes around the screen from the outside in.
 */
public class Aperture implements Curtain {
	private final GraphicsContext gc;

	private Coord centre;

	/**
	 * The radius of the Aperture. <code>0</code> means it is fully shut.
	 * {@link #maxRadius} it is fully open.
	 */
	private int radius;

	private int targetRadius;

	/**
	 * How big does the Aperture need to get before you cannot see it?
	 */
	private int maxRadius;

	private int targetState;

	private long squareDistance(Coord a, Coord b) {
		int xd = a.x - b.x;
		int yd = a.y - b.y;
		return xd * xd + yd * yd;
	}

	public Aperture(GraphicsContext gc) {
		this.gc = gc;
		setCentre(new Coord(gc.screenWidth()/2, gc.screenHeight()/2));
		current(OPEN);
		target(OPEN);
	}

	@Override
	public void update() {
		radius = Math.min(radius, maxRadius);
		radius = Math2.closer(radius, targetRadius, 1);
	}

	public void setCentre(Coord centre) {
		this.centre = centre.copy();

		// work out a derived value
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
		radius = maxRadius;
	}
	
	
	@Override
	public void draw() {
		if (radius != Integer.MAX_VALUE) {
			if (radius == 0) {
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xff000000);
			}
			else {
				gc.aperture(radius, centre.x, centre.y, 0xff000000);
			}
		}
	}

	@Override
	public void current(int state) {
		radius = stateToRadius(state);
	}

	private int stateToRadius(int state) {
		if (state==OPEN) return maxRadius;
		return 0;
	}

	@Override
	public void target(int state) {
		targetRadius = stateToRadius(state);
		targetState = state;
	}

	@Override
	public int target() {
		return targetState;
	}

	@Override
	public boolean isDone() {
		return radius==targetRadius;
	}
}
