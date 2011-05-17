package com.nney.tt.mapper;

import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;

public class BatRecord {
	public final BatAddress address;
	public final Box collisionBox;
	public final Coord where;

	BatRecord(BatAddress address, Box collisionBox, Coord where) {
		this.address = address;
		this.collisionBox = collisionBox;
		this.where = where;
	}

}
