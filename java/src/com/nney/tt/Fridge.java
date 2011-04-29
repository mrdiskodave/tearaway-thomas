package com.nney.tt;

import java.util.LinkedList;
import java.util.ListIterator;

public class Fridge<T extends Fridge.Content> {
	private LinkedList<T> content = new LinkedList<T>();
	private String name;
	
	public interface Content {
		int getRestoreDistance();
	}
	
	public Fridge(String name) {
		this.name = name;
	}

	public void freezeInto(T alien, int restore) {
		System.out.println(String.format("Freezing %x into %s with %d", alien.hashCode(), name, restore));
		ListIterator<T> fi = content.listIterator();
		while (fi.hasNext()) {
			if (fi.next().getRestoreDistance() >= restore) {
				fi.previous();
				break;
			}
		}
		fi.add(alien);
	}
	
	public T defrostFrom(int restore) {
		T a = content.peekFirst();
		if (a==null || a.getRestoreDistance() > restore) return null;
		System.out.println(String.format("Defrosting %x into %s with %d using %d", a.hashCode(), name, a.getRestoreDistance(), restore));
		assert a==content.removeFirst();
		return a;
	}
}
