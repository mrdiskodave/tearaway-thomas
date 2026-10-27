package com.nney.tt.aliens;

import com.nney.tt.geom.Coord;
import com.nney.tt.props.PropAnn;
import com.nney.utils.Math2;

public class PlainLiftAlien extends LiftAlien {
	@PropAnn(doc = "Where the lift starts from")
	public Coord start;

	@PropAnn(doc = "Where the lift ends up")
	public Coord end;

	@PropAnn(doc = "Our movement in relation to other identical things (0-99)")
	public int phase;

	@PropAnn(doc = "How long do we wait at either end?")
	public int pause;

	@PropAnn(doc = "Pixels moved per frame", min = 1, max = 8)
	public int speed = 1;

	/** Width the original game used for its lifts (from the AGL tables in s195). */
	private static final int ICE_LIFT_WIDTH = 36;
	private static final int FUTURE_LIFT_WIDTH = 38;
	private static final int BLOCK_LIFT_WIDTH = 24;

	/**
	 * Two kinds of legacy lift come here:
	 * 
	 * Type 0 (lift_alien/move_Vlift): goes straight up and down between OBtop
	 * and OBbottom, 2 pixels a frame, no pause. (The original drew it with map
	 * blocks; we use the world's lift sprite instead.)
	 * 
	 * Type 54 (ilift_alien/frac_lift), and 98 (flift1_alien, Futureland's
	 * version, which uses the same code): goes between (OBleft, OBtop) and
	 * (OBright, OBbottom), 2 pixels a frame along whichever axis is longer,
	 * no pause. OBstatus0 says which way it was going when the map was saved
	 * (non-zero: towards the larger coordinate). With the "climb" flag the
	 * other coordinate stays put rather than following the diagonal.
	 * 
	 * The original's x was the lift's left edge; ours is its middle.
	 */
	@Override
	public void loadFromLegacyData() {
		int type = loadByte(OBtype);
		Coord at = getLocationFromLegacy();
		boolean increasing;
		int half;
		if (type == 0) {
			half = BLOCK_LIFT_WIDTH / 2;
			int x = (at.x & -16) + 5 + half;
			start = new Coord(x, (short) loadShort(OBtop));
			end = new Coord(x, (short) loadShort(OBbottom));
			increasing = Math2.bitTest(loadByte(OBstatus0), 0);
		}
		else {
			half = (type == 98 ? FUTURE_LIFT_WIDTH : ICE_LIFT_WIDTH) / 2;
			start = new Coord((short) loadShort(OBleft) + half, (short) loadShort(OBtop));
			end = new Coord((short) loadShort(OBright) + half, (short) loadShort(OBbottom));
			increasing = loadByte(OBstatus0) != 0;
			if (Math2.bitTest(loadByte(OBflags), OBFclimb)) {
				// straight along the long axis: the other coordinate stays put
				if (isMajorX()) start.y = end.y = at.y;
				else start.x = end.x = at.x + half;
			}
		}
		speed = 2;
		pause = 0;
		phase = phaseFor(new Coord(at.x + half, at.y), increasing);
	}

	/** OBFclimb in s195. */
	private static final int OBFclimb = 3;

	private boolean isMajorX() {
		Coord delta = end.sub2(start);
		return Math.abs(delta.x) > Math.abs(delta.y);
	}

	/** The location a legacy alien was given before loadFromLegacyData. */
	private Coord legacyLocation = new Coord();

	private Coord getLocationFromLegacy() {
		return legacyLocation;
	}

	@Override
	public void resetTo(Coord c) {
		legacyLocation = c.copy();
		start = c.copyAndAdd(50, 0);
		end = c.copyAndAdd(-50, 0);
		phase = 0;
		pause = 50;
	}

	/**
	 * Phase (0-99) that puts us where the original lift was, going the same
	 * way.
	 * 
	 * @param at
	 *            Where it was (in our coordinates: middle of the lift).
	 * @param increasing
	 *            Was it heading for larger coordinates?
	 */
	private int phaseFor(Coord at, boolean increasing) {
		Coord delta = end.sub2(start);
		boolean majorX = isMajorX();
		int span = Math.max(1, majorX ? Math.abs(delta.x) : Math.abs(delta.y));
		int offset = majorX ? Math.abs(at.x - start.x) : Math.abs(at.y - start.y);
		boolean endIsLarger = majorX ? delta.x > 0 : delta.y > 0;
		boolean towardsEnd = increasing == endIsLarger;
		offset = Math.max(0, Math.min(span, offset));
		int t = towardsEnd ? offset : 2 * span - offset;
		return Math.round(100f * t / (2 * span)) % 100;
	}


	@Override
	protected Coord[] currentPosition() {
		Coord delta = end.sub2(start);
		Coord absDelta = new Coord(Math.abs(delta.x), Math.abs(delta.y));

		boolean majorX = absDelta.x > absDelta.y;
		int big = majorX ? absDelta.x : absDelta.y;

		int s = Math.max(1, speed);
		int len = Wave.sawToothWaveWithPauseCycleLength(big, pause * s);
		int pos = Wave.sawToothWaveWithPause(srv.getFrameNumber() * s + Math2.percent(len, phase), big, pause * s).pos;
		float frac = pos;
		frac /= big;
		if (majorX) {
			delta.x = pos * Integer.signum(delta.x);
			delta.y = Math.round(delta.y * frac);
		}
		else {
			delta.x = Math.round(delta.x * frac);
			delta.y = pos * Integer.signum(delta.y);
		}

		delta.add(start);
		return new Coord[] { delta };
	}
}
