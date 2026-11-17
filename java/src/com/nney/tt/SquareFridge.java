package com.nney.tt;

import java.util.Iterator;
import java.util.List;

import com.nney.tt.geom.Box;

/**
 * A Square Fridge.
 * 
 * It's 2D so it keeps four {@link Fridge}s internally: top, bottom, left and
 * right.
 * 
 * @param <T>
 *            The type that we contain.
 */
public class SquareFridge<T extends Bounded> implements Iterable<T> {
	final private Fridge<T> freezeTop = new Fridge<>("top");
	final private Fridge<T> freezeBottom = new Fridge<>("bottom");
	final private Fridge<T> freezeLeft = new Fridge<>("left");
	final private Fridge<T> freezeRight = new Fridge<>("right");

	private boolean froze(T t, Box screenBox) {
		Box fb = t.getBounds();
		if (fb != null) {
			if (fb.right < screenBox.left) {
				freezeLeft.add(t, -fb.right);
				return true;
			}
			else if (fb.bottom < screenBox.top) {
				freezeTop.add(t, -fb.bottom);
				return true;
			}
			else if (fb.left > screenBox.right) {
				freezeRight.add(t, fb.left);
				return true;
			}
			else if (fb.top > screenBox.bottom) {
				freezeBottom.add(t, fb.top);
				return true;
			}
		}
		return false;
	}

	/**
	 * Take out whatever the edge has reached. Something can come back past one
	 * edge and still be off-screen past another (it was off diagonally): that
	 * goes straight into the other fridge instead. It can't go back into the
	 * one it came from, since it's no longer beyond that edge, and the one it
	 * goes into won't let it out this frame either.
	 */
	private void defrostFrom(List<T> got, Fridge<T> fridge, int edge, Box screenBox) {
		for (;;) {
			T a = fridge.pop(edge);
			if (a == null) break;
			if (!froze(a, screenBox)) got.add(a);
		}
	}

	/**
	 * Defrost any objects that have come back on-screen. Ones that are still
	 * off-screen in another direction are moved to that direction's fridge.
	 *
	 * @param current
	 *            A list of objects to which on-screen ones will be added (and
	 *            removed from this object).
	 * @param screenBox
	 *            The bounds of the screen.
	 */
	public void defrostAny(List<T> current, Box screenBox) {
		defrostFrom(current, freezeLeft, -screenBox.left, screenBox);
		defrostFrom(current, freezeTop, -screenBox.top, screenBox);
		defrostFrom(current, freezeRight, screenBox.right, screenBox);
		defrostFrom(current, freezeBottom, screenBox.bottom, screenBox);
	}

	/**
	 * Freeze any objects that are off-screen.
	 * 
	 * @param current
	 *            A list of objects from which off-screen ones will be removed
	 *            and stored in this object.
	 * @param screenBox
	 *            The bounds of the screen.
	 */
	public void freezeAny(List<T> current, Box screenBox) {
		for (Iterator<T> iterator = current.iterator(); iterator.hasNext();) {
			T alien = iterator.next();
			if (froze(alien, screenBox)) {
				iterator.remove();
			}
		}
	}

	@Override
	public Iterator<T> iterator() {
		ConcatenatedIterator<T> it = new ConcatenatedIterator<>();
		it.add(freezeLeft);
		it.add(freezeTop);
		it.add(freezeRight);
		it.add(freezeBottom);
		return it;
	}
}
