package com.nney.tt;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

public class AlienTracker {
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

	private void add(Alien alien) {
		alienLists.get(alien.depth).add(alien);
	}

	public void delayedAdd(Alien alien) {
		delayedAdditions.add(alien);
	}

	public void begin(Box screenBox) {
		// delayed
		for (Alien alien : delayedAdditions) {
			add(alien);
		}
		delayedAdditions.clear();

		// defrosted
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	public boolean perhapsFreeze(Alien alien, Box screenBox) {
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

	public List<Alien> getForegroundList() {
		return alienLists.get(Alien.DEPTH_FOREGROUND);
	}

	public List<Alien> getBackgroundList() {
		return alienLists.get(Alien.DEPTH_BACKGROUND);
	}

	static private void visitIt(Visitor<Alien> v, List<Alien> l) {
		for (Alien a : l) {
			v.visit(a);
		}
	}

	public void visitVisible(Visitor<Alien> v) {
		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
			visitIt(v, alienLists.get(x));
		}
	}

	public void visitAll(Visitor<Alien> v) {
		visitVisible(v);
		freezeBottom.visit(v);
		freezeTop.visit(v);
		freezeLeft.visit(v);
		freezeRight.visit(v);
	}

	private void clearAll() {
		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
			alienLists.get(x).clear();
		}
		freezeBottom.clear();
		freezeTop.clear();
		freezeLeft.clear();
		freezeRight.clear();
	}

//	private void visitAllVisibleAlienLists(Visitor<List<Alien>> v) {
//		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
//			v.visit(alienLists.get(x));
//		}
//	}
//	
//	private void visitAllFridges(Visitor<Fridge> v) {
//		v.visit(freezeBottom);
//		v.visit(freezeTop);
//		v.visit(freezeLeft);
//		v.visit(freezeRight);
//	}
	
	public void reclassify() {
		visitAll(new Visitor<Alien>() {
			@Override
			public void visit(Alien a) {
				delayedAdditions.add(a);
			}
		});
		clearAll();
	}
}
