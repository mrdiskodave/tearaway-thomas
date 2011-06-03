package com.nney.tt.mapper;

import com.nney.tt.Visitor;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

public class NearestAlienFinder implements Visitor<Alien> {
	long dist = Long.MAX_VALUE;
	private final Coord o;
	private Alien nearest;

	public NearestAlienFinder(Coord o) {
		this.o = o;

	}

	@Override
	public void visit(Alien a) {
		Coord diff = a.getLocation().sub2(o);
		long ndist = diff.x * diff.x + diff.y * diff.y;
		if (ndist < dist) {
			dist = ndist;
			nearest = a;
		}
	};

	public Alien getAnswer() {
		return nearest;
	}
}
