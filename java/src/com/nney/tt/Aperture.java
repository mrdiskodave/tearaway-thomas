package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;

public class Aperture {
	private final GraphicsContext gc;

	private Coord centre;

	/**
	 * The radius of the Aperture. <code>0</code> means it is fully shut.
	 * {@link #maxRadius} it is fully open.
	 */
	private int radius;

	/**
	 * <code>1</code> it is growing. <code>-1</code> it is shrinking.
	 * <code>0</code> it is just sitting there.
	 */
	private int direction;

	/**
	 * How big does the Aperture need to get before you cannot see it?
	 */
	private int maxRadius;

	private long squareDistance(Coord a, Coord b) {
		int xd = a.x - b.x;
		int yd = b.y - b.y;
		return xd * xd + yd * yd;
	}

	public Aperture(GraphicsContext gc) {
		this.gc = gc;
	}

	synchronized public void update() {
		radius = Math.min(radius, maxRadius);
		if (direction != 0) {
			if (direction > 0) {
				// expand
				if (radius >= maxRadius) {
					direction = 0;
				}
				else {
					radius++;
				}
			}
			else {
				if (radius == 0) {
					direction = 0;
				}
				else {
					radius--;
				}
			}
		}
	}

	synchronized public void setJob(Coord centre, int direction) {
		// set it
		this.centre = centre.copy();
		this.direction = direction;

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
		radius = direction < 0 ? maxRadius : 0;
	}

	synchronized public void draw() {
		if (radius != Integer.MAX_VALUE) {
			if (radius == 0) {
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0xff000000);
			}
			else {
				gc.aperture(radius, centre.x, centre.y, 0xff000000);
			}
		}
	}

	synchronized public boolean isJobRunning() {
		return direction != 0;
	}
}
