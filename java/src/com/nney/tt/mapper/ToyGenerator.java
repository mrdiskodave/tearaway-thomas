package com.nney.tt.mapper;

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

	private int get(S s) {
		Integer answer = where.get(s.flattern());
		assert answer != null;
		return answer;
	}

	private int isWall(int b) {
		return S.rWalls.much(b);
	}

	private int isSpace(int b) {
		return S.rSpaces.much(b);
	}

	private int isSpecial(int b) {
		return S.rSpecial.much(b);
	}

	private S testWall(Coord coord, int i, int j) {
		return S.fromBlock(blockAccess.get(coord.copyAndAdd(i, j)));
	}

	static class DelayedWriter {
		private static final int CAPACITY = 2;
		private int[][] queue = new int[CAPACITY][];
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
			System.arraycopy(queue, 1, queue, 0, CAPACITY - 1);
			queue[CAPACITY - 1] = row;
		}

		void flush() {
			while (y < ba.height()) {
				put(null);
			}
		}
	}

	public void run() {
		System.out.println("Generating Intricacies Of Toyland");
		DelayedWriter dw = new DelayedWriter(blockAccess);
		for (int y = 0; y < blockAccess.height(); y++) {
			int[] out = new int[blockAccess.width()];
			for (int x = 0; x < blockAccess.width(); x++) {
				Coord coord = new Coord(x, y);

				boolean checkers = ((x ^ y) & 1)==0;

				S east = testWall(coord, 1, 0);
				S west = testWall(coord, -1, 0);
				S northWest = testWall(coord, -1, -1);
				S north = testWall(coord, 0, -1);
				S south = testWall(coord, 0, 1);
				S here = testWall(coord, 0, 0);
				// boolean wallSouth = testWall(coord, 0, 1);

				int walls[] = WALL_TABLE;
				int shadows[] = SHADOW_TABLE;

				int b = blockAccess.get(coord);
				out[x] = b;
				
				int n = -1;
				
				if (here.isWall()) {
					int v = 0;
					if (west.isWall()) v |= 1;
					if (east.isWall()) v |= 2;
					// System.out.println("WALL:"+v);
					v = walls[v];
					// System.out.println("WALL2:"+v);
					n = get(s().wall(v).col(here.col()));
				}
				else if (here.special() == S.HIDDEN) {
					int b2 = blockAccess.get(coord.copyAndAdd(0, 1));
					b2 = isSpace(b2);
					if (b2 >= 0) {
						S s = s().space(b2).which(checkers).special(S.HIDDEN);
						n = get(s);
						System.out.println(String.format("Special! %03d %08x %s ", n, s.flattern(), s));
						// 00002f01??????
					}
				}
				else if (here.isSpace()) {
					int v = 0;
					if (north.isWall()) v |= 1;
					if (northWest.isWall()) v |= 2;
					if (west.isWall()) v |= 4;
					v = shadows[v];
					if (v >= 0) {
						S soFar = s().space(here.space()).which(checkers).shadow(v);
						if (south.isWall()) {
							soFar.pips(true).col(south.col());
						}
						n = get(soFar);
					}
				}
				else {
					System.out.println(String.format("Something else: %s '%s' at %s", b, here, coord));
				}

				if (n >= 0) {
					out[x] = n;
				}
			}
			dw.put(out);
		}
		dw.flush();
	}

}
