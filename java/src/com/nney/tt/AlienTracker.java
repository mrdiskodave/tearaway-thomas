package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.utils.ListUtil;
import com.nney.utils.ReadOnlyIterator;

public abstract class AlienTracker implements Iterable<Alien> {
	final private Fridge<Alien> freezeTop = new Fridge<Alien>("top");
	final private Fridge<Alien> freezeBottom = new Fridge<Alien>("bottom");
	final private Fridge<Alien> freezeLeft = new Fridge<Alien>("left");
	final private Fridge<Alien> freezeRight = new Fridge<Alien>("right");

	private void defrostAnyFrom(Fridge<Alien> fridge, int restore) {
		for (;;) {
			Alien a = fridge.pop(restore);
			if (a == null) break;
			add(a);
		}
	}

	public void add(Iterable<Alien> l) {
		for (Alien a : l) {
			add(a);
		}
	}

	public void defrostAny(Box screenBox) {
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	public boolean perhapsFreeze(Alien alien, Box screenBox) {
		assert !alien.remove;
		Box fb = alien.freezeBounds;
		if (fb != null) {
			if (fb.right < screenBox.left) {
				freezeLeft.add(alien, -fb.right);
				return true;
			}
			else if (fb.bottom < screenBox.top) {
				freezeTop.add(alien, -fb.bottom);
				return true;
			}
			else if (fb.left > screenBox.right) {
				freezeRight.add(alien, fb.left);
				return true;
			}
			else if (fb.top > screenBox.bottom) {
				freezeBottom.add(alien, fb.top);
				return true;
			}
		}
		return false;
	}

	@Override
	public Iterator<Alien> iterator() {
		ConcatenatedIterator<Alien> ci = new ConcatenatedIterator<Alien>();
		for (Iterable<Alien> it : lists()) {
			ci.add(it);
		}
		return ReadOnlyIterator.wrap(ci);
	}

	public List<Alien> getAll() {
		List<Alien> answer = new ArrayList<Alien>();
		for (Iterable<Alien> it : lists()) {
			ListUtil.copy(answer, it);
		}
		return answer;
	}

	private List<Iterable<Alien>> lists() {
		ArrayList<Iterable<Alien>> answer = new ArrayList<Iterable<Alien>>();
		getExtraLists(answer);
		answer.add(freezeBottom);
		answer.add(freezeTop);
		answer.add(freezeLeft);
		answer.add(freezeRight);
		return answer;
	}

	protected abstract void getExtraLists(ArrayList<Iterable<Alien>> answer);

	public abstract void add(Alien a);
}
