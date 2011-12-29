package com.nney.tt.toygen;

import java.util.Map;

import com.nney.tt.BlockAccess;
import com.nney.tt.geom.Coord;

public class ToyGenerator {
	private static final int[] WALL_TABLE = { 3, 2, 0, 1 };
	private static final int[] SHADOW_TABLE = { 0, 5, 3, 2, 4, -1, 6, 1 };
	private final Map<Integer, Integer> where;
	private final BlockAccess blockAccess;

	public ToyGenerator(BlockAccess blockAccess, Map<Integer, Integer> where) {
		this.blockAccess = blockAccess;
		this.where = where;
	}

	static private S s() {
		return new S();
	}

	private S readOrDefault(Coord coord, int dx, int dy) {
		Coord t = coord.copyAndAdd(dx, dy);
		S answer = read(t);
		if (answer == null) answer = s();
		return answer;
	}

	public S read(Coord coord) {
		return S.fromBlock(blockAccess.get(coord));
	}

	static class Fail extends RuntimeException {
		private static final long serialVersionUID = 1L;

		public Fail(String message) {
			super(message);
		}
	}

	public void run() {
		System.out.println("Generating the intricacies of toyland");
		DelayedBlockWriter dw = new DelayedBlockWriter(blockAccess, 2);
		for (int y = 0; y < blockAccess.height(); y++) {
			short[] row = new short[blockAccess.width()];
			for (int x = 0; x < blockAccess.width(); x++) {
				Coord coord = new Coord(x, y);
				try {

					boolean checkers = ((x ^ y) & 1) == 0;

					S here = readOrDefault(coord, 0, 0);
					S northWest = readOrDefault(coord, -1, -1);
					S north = readOrDefault(coord, 0, -1);
					S west = readOrDefault(coord, -1, 0);
					S east = readOrDefault(coord, 1, 0);
					S south = readOrDefault(coord, 0, 1);

					S out;
					if (here.isWall()) {
						int v = 0;
						if (west.isWall()) v |= 1;
						if (east.isWall()) v |= 2;
						v = WALL_TABLE[v];
						out = s().wall(v).col(here.col());
					}
					else if (here.isSpecial()) {
						int s = here.special();
						out = s().space(spaceFrom(coord, north, south, east, west)).which(checkers).special(s);
					}
					else if (here.isSpace()) {
						int v = 0;
						if (north.isWall()) v |= 1;
						if (northWest.isWall()) v |= 2;
						if (west.isWall()) v |= 4;
						v = SHADOW_TABLE[v];
						if (v >= 0) {
							out = s().space(here.space()).which(checkers).shadow(v);
							if (south.isWall()) {
								out.pips(true).col(south.col());
							}
						}
						else {
							throw new Fail("Cannot do this shaddow");
						}
					}
					else {
						throw new Fail("Bogus input block");
					}

					Integer answer = where.get(out.flattern());
					if (answer == null) {
						throw new Fail("Made something we cannot covert back");
					}
					row[x] = answer.shortValue();
				}
				catch (Fail e) {
					System.out.println(String.format("Error: %s at %s", e.getMessage(), coord));
				}
			}
			dw.put(row);
		}
		dw.flush();
	}

	private int spaceFrom(Coord c, S... ss) {
		for (S s : ss) {
			if (s.isSpace()) return s.space();
		}
		throw new Fail("Cannot find an adjactent space");
	}
}
