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
 */
public class SquareFridge<T extends Bounded> implements Iterable<T> {
	final private Fridge<T> freezeTop = new Fridge<T>("top");
	final private Fridge<T> freezeBottom = new Fridge<T>("bottom");
	final private Fridge<T> freezeLeft = new Fridge<T>("left");
	final private Fridge<T> freezeRight = new Fridge<T>("right");

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

	private void defrostFrom(List<T> got, Fridge<T> fridge, int restore) {
		for (;;) {
			T a = fridge.pop(restore);
			if (a == null) break;
			got.add(a);
		}
	}

	/**
	 * Defrost any objects that have come back on-screen.
	 * 
	 * @param current
	 *            A list of objects to which on-screen ones will be added (and
	 *            removed from this object).
	 * @param screenBox
	 *            The bounds of the screen.
	 */
	public void defrostAny(List<T> current, Box screenBox) {
		defrostFrom(current, freezeLeft, -screenBox.left);
		defrostFrom(current, freezeTop, -screenBox.top);
		defrostFrom(current, freezeRight, screenBox.right);
		defrostFrom(current, freezeBottom, screenBox.bottom);
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
		ConcatenatedIterator<T> it = new ConcatenatedIterator<T>();
		it.add(freezeLeft);
		it.add(freezeTop);
		it.add(freezeRight);
		it.add(freezeBottom);
		return it;
	}
}
