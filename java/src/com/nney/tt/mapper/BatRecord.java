package com.nney.tt.mapper;

import com.nney.tt.geom.Box;

public class BatRecord {
	public final BatAddress who;
	public final Box where;

	BatRecord(BatAddress who, Box where) {
		this.who = who;
		this.where = where;
	}

}
