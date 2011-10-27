package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.AlienTracker;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

/**
 * An {@link AlienTracker} optimised for simplicity.
 */
public class MapperAlienTracker extends AlienTracker {
	final private List<Alien> alienList = new LinkedList<Alien>();

	public List<Alien> getOnScreen() {
		return alienList;
	}

	@Override
	public void add(Alien alien) {
		alienList.add(alien);
	}

	public void begin(Box screenBox) {
		defrostAny(screenBox);
	}

	@Override
	protected void getExtraLists(ArrayList<Iterable<Alien>> answer) {
		answer.add(alienList);
	}
}
