package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;

import com.nney.tt.geom.Coord;

public class CollidableList<T extends Collidable> implements Iterable<T> {
	private ArrayList<T> content = new ArrayList<T>();

	public T get(int x) {
		return content.get(x);
	}

	public void add(T t) {
		content.add(t);
	}

	public void clear() {
		content.clear();
	}

	public T find(Coord c) {
		for (T t : content) {
			if (t.inside(c)) return t;
		}
		return null;
	}

	@Override
	public Iterator<T> iterator() {
		return content.iterator();
	}

}
