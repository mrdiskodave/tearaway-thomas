package com.nney.tt;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.utils.ListUtil;

/**
 * An {@link AlienTracker} optimised for speed. It keeps it's on-screen lists
 * separated by depth and it supports delayed additions.
 */
public class GameAlienTracker extends AlienTracker {
	final private List<List<Alien>> alienLists;

	final private List<Alien> delayedAdditions = new LinkedList<Alien>();

	public GameAlienTracker() {
		alienLists = new ArrayList<List<Alien>>();
		for (int x = 0; x < Alien.DEPTH_MAX; x++) {
			alienLists.add(new LinkedList<Alien>());
		}
	}

	public List<Alien> getOnScreen(int x) {
		return alienLists.get(x);
	}

	@Override
	public void add(Alien alien) {
		assert !alien.remove;
		alienLists.get(alien.depth).add(alien);
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

		// defrosted
		defrostAny(screenBox);
	}

	@Override
	protected void getExtraLists(ArrayList<Iterable<Alien>> answer) {
		answer.add(delayedAdditions);
		for (List<Alien> aliens : alienLists) {
			answer.add(aliens);
		}
	}
}
