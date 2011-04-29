package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

import com.nney.tt.aliens.Alien;

public class Fridge {
	private LinkedList<Alien> content = new LinkedList<Alien>();
	private String name;
	
	public Fridge(String name) {
		this.name = name;
	}

	public void freezeInto(Alien alien, Iterator<Alien> alienIterator, int restore) {
		System.out.println(String.format("Freezing %x into %s with %d", alien.hashCode(), name, restore));
		alienIterator.remove();
		alien.restore = restore;

		ListIterator<Alien> fi = content.listIterator();
		while (fi.hasNext()) {
			if (fi.next().restore >= restore) {
				fi.previous();
				break;
			}
		}
		fi.add(alien);
	}
	
	public Alien defrostFrom(int restore) {
		Alien a = content.peekFirst();
		if (a==null || a.restore > restore) return null;
		System.out.println(String.format("Defrosting %x into %s with %d using %d", a.hashCode(), name, a.restore, restore));
		assert a==content.removeFirst();
		return a;
	}
}
