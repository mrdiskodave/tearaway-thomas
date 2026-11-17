package com.nney.tt;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.geom.Box;

import junit.framework.TestCase;

public class SquareFridgeTest extends TestCase {
	private static class Thing implements Bounded {
		final Box bounds;

		Thing(int left, int top, int right, int bottom) {
			bounds = new Box(left, top, right, bottom);
		}

		@Override
		public Box getBounds() {
			return bounds;
		}
	}

	private final SquareFridge<Thing> fridge = new SquareFridge<Thing>();

	private List<Thing> freeze(Box screen, Thing... things) {
		List<Thing> current = new ArrayList<Thing>(List.of(things));
		fridge.freezeAny(current, screen);
		return current;
	}

	private List<Thing> defrost(Box screen) {
		List<Thing> got = new ArrayList<Thing>();
		fridge.defrostAny(got, screen);
		return got;
	}

	private int frozen() {
		int n = 0;
		for (@SuppressWarnings("unused")
		Thing t : fridge) {
			n++;
		}
		return n;
	}

	public void testOnScreenStaysOut() {
		Thing t = new Thing(10, 10, 20, 20);
		assertEquals(List.of(t), freeze(new Box(0, 0, 100, 100), t));
		assertEquals(0, frozen());
	}

	public void testComesBackWhenTheScreenReachesIt() {
		Thing t = new Thing(150, 10, 160, 20);
		assertTrue(freeze(new Box(0, 0, 100, 100), t).isEmpty());
		assertTrue(defrost(new Box(40, 0, 140, 100)).isEmpty());
		assertEquals(List.of(t), defrost(new Box(60, 0, 160, 100)));
		assertEquals(0, frozen());
	}

	public void testDiagonalGoesStraightIntoTheOtherFridge() {
		// up and to the left: frozen to the left
		Thing t = new Thing(-50, -50, -40, -40);
		assertTrue(freeze(new Box(0, 0, 100, 100), t).isEmpty());

		// the screen moves left past it, but it's still above: it must not
		// come out, even for a frame
		assertTrue(defrost(new Box(-60, 0, 40, 100)).isEmpty());
		assertEquals(1, frozen());

		// then up to it
		assertEquals(List.of(t), defrost(new Box(-60, -60, 40, 40)));
		assertEquals(0, frozen());
	}

	public void testDiagonalIntoAFridgeAlreadyDefrosted() {
		// above: frozen at the top
		Thing t = new Thing(10, -50, 20, -40);
		assertTrue(freeze(new Box(0, 0, 100, 100), t).isEmpty());

		// the screen goes up past it and right: it comes out of the top
		// fridge (done after the left one) and must go into the left one
		assertTrue(defrost(new Box(30, -60, 130, 40)).isEmpty());
		assertEquals(1, frozen());

		// stays there until the screen comes back left
		assertTrue(defrost(new Box(25, -60, 125, 40)).isEmpty());
		assertEquals(List.of(t), defrost(new Box(0, -60, 100, 40)));
		assertEquals(0, frozen());
	}
}
