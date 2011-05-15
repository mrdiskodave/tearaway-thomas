package com.nney.tt.mapper;

import com.nney.tt.AlienVisitor;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Coord;

public class NearestAlienFinder implements AlienVisitor {
	long dist = Long.MAX_VALUE;
	private final Coord o;
	private Alien nearest;

	public NearestAlienFinder(Coord o) {
		this.o = o;

	}

	@Override
	public void visit(Alien a) {
		Coord diff = a.c.copy();
		diff.sub(o);
		long ndist = diff.x*diff.x + diff.y*diff.y;
		System.out.println("Dist"+ndist);
		if (ndist<dist) {
			System.out.println("BEtter!");
			dist = ndist;
			nearest = a;
		}
	};
	
	public Alien getAnswer() {
		return nearest;
	}
}
