package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;

import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;

public class AlienTracker {
	private List<Alien> backgroundAlienList = new LinkedList<Alien>();
	private List<Alien> foregroundAlienList = new LinkedList<Alien>();
	private List<Alien> freshAlienList = new LinkedList<Alien>();

	private Fridge<Alien> freezeTop = new Fridge<Alien>("top");
	private Fridge<Alien> freezeBottom = new Fridge<Alien>("bottom");
	private Fridge<Alien> freezeLeft = new Fridge<Alien>("left");
	private Fridge<Alien> freezeRight = new Fridge<Alien>("right");

	// ---------------------------------------------------------------------------
	// REFRIGERATION
	
	public boolean perhapsFreezeOne(Alien alien, Iterator<Alien> alienIterator, Box screenBox) {
		Box fb = alien.freezeBounds;
		if (fb == null) {
			return false;
		}
		if (fb.right < screenBox.left) {
			freezeOne(alien, alienIterator, freezeLeft, -fb.right);
		}
		else if (fb.bottom < screenBox.top) {
			freezeOne(alien, alienIterator, freezeTop, -fb.bottom);
		}
		else if (fb.left > screenBox.right) {
			freezeOne(alien, alienIterator, freezeRight, fb.left);
		}
		else if (fb.top > screenBox.bottom) {
			freezeOne(alien, alienIterator, freezeBottom, fb.top);
		}
		else {
			return false;
		}
		return true;
	}

	private void freezeOne(Alien alien, Iterator<Alien> alienIterator, Fridge<Alien> fridge, int restore) {
		alienIterator.remove();
		fridge.add(alien, restore);
	}

	private void defrostAnyFrom(Fridge<Alien> fridge, int restore) {
		for (;;) {
			Alien a = fridge.remove(restore);
			if (a==null) break;
			addAlien(a);
		}
	}

	private void defrostAny(Box screenBox) {
		defrostAnyFrom(freezeLeft, -screenBox.left);
		defrostAnyFrom(freezeTop, -screenBox.top);
		defrostAnyFrom(freezeRight, screenBox.right);
		defrostAnyFrom(freezeBottom, screenBox.bottom);
	}

	private void addAlien(Alien alien) {
		List<Alien> target = alien.inFront ? foregroundAlienList : backgroundAlienList;
		target.add(alien);
	}

	public void addFresh(Alien alien) {
		freshAlienList.add(alien);
	}
	
	public void addFreshAndDefrosted(Box screenBox) {
		for (Alien alien: freshAlienList) {
			addAlien(alien);
		}
		freshAlienList.clear();
		
		defrostAny(screenBox);
	}

	public Iterator<Alien> foregroundAlienListIterator() {
		return foregroundAlienList.iterator();
	}

	public Iterator<Alien> getBackgroundAlienIterator() {
		return backgroundAlienList.iterator();
	}



}
