package com.nney.tt;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

public class GameAlienTracker {
	final private List<List<Alien>> alienListss = new ArrayList<List<Alien>>();

	final private List<Alien> delayedAdditions = new LinkedList<Alien>();

	final private SquareFridge<Alien> squareFridge = new SquareFridge<Alien>();

	public GameAlienTracker() {
		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
			alienListss.add(new LinkedList<Alien>());
		}
	}

	public List<Alien> getOnScreen(int x) {
		return alienListss.get(x);
	}

	public void add(Alien alien) {
		assert !alien.remove;
		alienListss.get(alien.depth).add(alien);
	}

	public void add(Iterable<Alien> l) {
		for (Alien a : l) {
			add(a);
		}
	}

	public void delayedAdd(Alien alien) {
		assert !alien.remove;
		delayedAdditions.add(alien);
	}

	public void begin(Box screenBox) {
		// delayed
		for (Alien alien : delayedAdditions) {
			add(alien);
		}
		delayedAdditions.clear();

		// do defrosting
		ArrayList<Alien> df = new ArrayList<Alien>();
		squareFridge.defrostAny(df, screenBox);
		add(df);
	}

	public void freezeAny(Box screenBox) {
		for (List<Alien> alienList : alienListss) {
			squareFridge.freezeAny(alienList, screenBox);
		}
	}
}
