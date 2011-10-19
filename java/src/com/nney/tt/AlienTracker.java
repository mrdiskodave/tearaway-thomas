package com.nney.tt;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

public class AlienTracker implements Iterable<Alien> {
	final private List<List<Alien>> alienLists;

	final private List<Alien> delayedAdditions = new LinkedList<Alien>();

	final private Fridge<Alien> freezeTop = new Fridge<Alien>("top");
	final private Fridge<Alien> freezeBottom = new Fridge<Alien>("bottom");
	final private Fridge<Alien> freezeLeft = new Fridge<Alien>("left");
	final private Fridge<Alien> freezeRight = new Fridge<Alien>("right");

	public AlienTracker() {
		alienLists = new ArrayList<List<Alien>>();
		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
			alienLists.add(new LinkedList<Alien>());
		}
	}

	private void defrostAnyFrom(Fridge<Alien> fridge, int restore) {
		for (;;) {
			Alien a = fridge.remove(restore);
			if (a == null) break;
			add(a);
		}
	}

	public void add(Alien alien) {
		assert !alien.remove;
		alienLists.get(alien.depth).add(alien);
	}

	public void delayedAdd(Alien alien) {
		assert !alien.remove;
		delayedAdditions.add(alien);
	}
	
	public void defrost(Alien alien) {
		boolean defrosted = freezeLeft.delete(alien) || freezeTop.delete(alien) || freezeRight.delete(alien) || freezeBottom.delete(alien);
		if (defrosted) add(alien);
	}

	public void begin(Box screenBox) {
		// delayed
		doDelayedAdditions();

		// defrosted
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	private void doDelayedAdditions() {
		for (Alien alien : delayedAdditions) {
			add(alien);
		}
		delayedAdditions.clear();
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
	
	public void slowDefrostRequest(Alien a) {
		
	}

	public List<Alien> get(int x) {
		return alienLists.get(x);
	}

	@Override
	public Iterator<Alien> iterator() {
		ConcatenatedIterator<Alien> ci = new ConcatenatedIterator<Alien>();
		ci.add(freezeBottom);
		ci.add(freezeTop);
		ci.add(freezeLeft);
		ci.add(freezeRight);
		ci.add(delayedAdditions);
		for (List<Alien> aliens: alienLists) {
			ci.add(aliens);
		}
		return ci;
	}
}
