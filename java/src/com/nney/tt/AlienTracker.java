package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

public class AlienTracker {
	final private List<Alien> backgroundAlienList = new LinkedList<Alien>();
	final private List<Alien> foregroundAlienList = new LinkedList<Alien>();
	final private List<Alien> delayedAdditions = new LinkedList<Alien>();

	final private Fridge<Alien> freezeTop = new Fridge<Alien>("top");
	final private Fridge<Alien> freezeBottom = new Fridge<Alien>("bottom");
	final private Fridge<Alien> freezeLeft = new Fridge<Alien>("left");
	final private Fridge<Alien> freezeRight = new Fridge<Alien>("right");

	private void defrostAnyFrom(Fridge<Alien> fridge, int restore) {
		for (;;) {
			Alien a = fridge.remove(restore);
			if (a==null) break;
			addAlien(a);
		}
	}

	private void addAlien(Alien alien) {
		List<Alien> target = alien.inFront ? foregroundAlienList : backgroundAlienList;
		target.add(alien);
	}

	public boolean perhapsFreezeOne(Alien alien, Box screenBox) {
		Box fb = alien.freezeBounds;
		if (fb == null) {
			return false;
		}
		if (fb.right < screenBox.left) {
			freezeLeft.add(alien, (-fb.right));
		}
		else if (fb.bottom < screenBox.top) {
			freezeTop.add(alien, (-fb.bottom));
		}
		else if (fb.left > screenBox.right) {
			freezeRight.add(alien, fb.left);
		}
		else if (fb.top > screenBox.bottom) {
			freezeBottom.add(alien, fb.top);
		}
		else {
			return false;
		}
		return true;
	}

	public void delayedAdd(Alien alien) {
		delayedAdditions.add(alien);
	}
	
	public void restoreDelayedAndDefrosted(Box screenBox) {
		// delayed
		for (Alien alien: delayedAdditions) {
			addAlien(alien);
		}
		delayedAdditions.clear();
		
		// defrosted
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	public Iterator<Alien> getForegroundAlienListIterator() {
		return foregroundAlienList.iterator();
	}

	public Iterator<Alien> getBackgroundAlienIterator() {
		return backgroundAlienList.iterator();
	}
}
