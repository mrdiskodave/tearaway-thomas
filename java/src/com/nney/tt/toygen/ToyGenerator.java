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

	private S s() {
		return new S();
	}

	private S read(Coord coord, int i, int j) {
		Coord t = coord.copyAndAdd(i, j);
		S answer = S.fromBlock(blockAccess.get(t));
		if (answer == null) {
			System.out.println(String.format("Bad block at %s", t));
			answer = s();
		}
		return answer;
	}

	/**
	 * When computing a block {@link ToyGenerator#run()} needs to read the
	 * surrounding original blocks as input. If do we do this entirely in-place
	 * then, as we compute every block, we'll end up reading our output back in
	 * as input. One way around would be a full double-buffer but we only really
	 * need two rows of lee-way.
	 */
	static class DelayedWriter {
		private static final int CAPACITY_IN_ROWS = 2;
		private int[][] queue = new int[CAPACITY_IN_ROWS][];
		private final BlockAccess ba;
		private int y;

		public DelayedWriter(BlockAccess ba) {
			this.ba = ba;
		}

		void put(int[] row) {
			int[] leaving = queue[0];
			if (leaving != null) {
				for (int x = 0; x < ba.width(); x++) {
					ba.set(new Coord(x, y), leaving[x]);
				}
				y++;
			}
			System.arraycopy(queue, 1, queue, 0, CAPACITY_IN_ROWS - 1);
			queue[CAPACITY_IN_ROWS - 1] = row;
		}

		void flush() {
			while (y < ba.height()) put(null);
		}
	}

	public void run() {
		System.out.println("Generating the intricacies of toyland");
		DelayedWriter dw = new DelayedWriter(blockAccess);
		for (int y = 0; y < blockAccess.height(); y++) {
			int[] row = new int[blockAccess.width()];
			for (int x = 0; x < blockAccess.width(); x++) {
				Coord coord = new Coord(x, y);

				boolean checkers = ((x ^ y) & 1) == 0;

				S here = read(coord, 0, 0);
				S northWest = read(coord, -1, -1);
				S north = read(coord, 0, -1);
				S west = read(coord, -1, 0);
				S east = read(coord, 1, 0);
				S south = read(coord, 0, 1);

				S out = null;

				if (here.isWall()) {
					int v = 0;
					if (west.isWall()) v |= 1;
					if (east.isWall()) v |= 2;
					v = WALL_TABLE[v];
					out = s().wall(v).col(here.col());
				}
				else if (here.isSpecial()) {
					int s = here.special(); 
					S spaceFrom = null;
					if (s == S.SPECIAL_MAGIC) spaceFrom = south;
					if (spaceFrom!=null && spaceFrom.isSpace()) {
						out = s().space(spaceFrom.space()).which(checkers).special(s);
					}
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
				}

				if (out == null) {
					int in = blockAccess.get(coord);
					System.out.println(String.format("Something else: %s '%s' at %s", in, here, coord));
					row[x] = in;
				}
				else {
					Integer answer = where.get(out.flattern());
					assert answer != null;
					row[x] = answer;
				}
			}
			dw.put(row);
		}
		dw.flush();
	}
}
