package com.nney.tt;

import java.util.Iterator;
import java.util.List;

import com.nney.tt.geom.Box;

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

	public void defrostAny(List<T> got, Box screenBox) {
		defrostFrom(got, freezeLeft, -screenBox.left);
		defrostFrom(got, freezeTop, -screenBox.top);
		defrostFrom(got, freezeRight, screenBox.right);
		defrostFrom(got, freezeBottom, screenBox.bottom);
	}

	public void freezeAny(List<T> got, Box screenBox) {
		for (Iterator<T> iterator = got.iterator(); iterator.hasNext();) {
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
