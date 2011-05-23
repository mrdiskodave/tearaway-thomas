package com.nney.tt.mapper;

import com.nney.tt.geom.Coord;

public class BatRecord {
	public final BatAddress address;
	public final Coord where;

	BatRecord(BatAddress address, Coord where) {
		this.address = address;
		this.where = where;
	}

	public boolean inside(Coord c) {
		return BatGCImpl.boxForBat(where).inside(c);
	}
}
