package com.nney.tt.mapper;

import java.util.Map;

import com.nney.tt.BlockAccess;
import com.nney.tt.geom.Coord;

public class ToyGenerator {
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
		return ToyMaker.rWalls.much(b);
	}

	private int isSpace(int b) {
		return ToyMaker.rSpaces.much(b);
	}

	private int isSpecial(int b) {
		return ToyMaker.rSpecial.much(b);
	}

	private boolean testWall(Coord coord, int i, int j) {
		int b = blockAccess.get(coord.copyAndAdd(i, j));
		return isWall(b) >= 0;
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

				int checkers = (x ^ y) & 1;

				boolean wallEast = testWall(coord, 1, 0);
				boolean wallWest = testWall(coord, -1, 0);
				boolean wallNorthWest = testWall(coord, -1, -1);
				boolean wallNorth = testWall(coord, 0, -1);
				// boolean wallSouth = testWall(coord, 0, 1);

				int walls[] = { 3, 2, 0, 1 };
				int shadows[] = { 0, 5, 3, 2, 4, -1, 6, 1 };

				int b = blockAccess.get(coord);
				out[x] = b;
				int wallColour = isWall(b);
				int spaceNumber = isSpace(b);
				int specialNumber = isSpecial(b);
				int n = -1;
				
				if (wallColour >= 0) {
					int v = 0;
					if (wallWest) v |= 1;
					if (wallEast) v |= 2;
					// System.out.println("WALL:"+v);
					v = walls[v];
					// System.out.println("WALL2:"+v);
					n = get(s().wall(v).col(wallColour));
				}
				else if (specialNumber >= 0) {
					System.out.println("Special");
					int b2 = blockAccess.get(coord.copyAndAdd(0, 1));
					b2 = isSpace(b2);
					if (b2 >= 0) {
						S s = s().style(b2, checkers).magic(true);
						n = get(s);
						System.out.println(String.format("Special! %03d %08x %s ", n, s.flattern(), s));
						// 00002f01??????
					}
				}
				else if (spaceNumber >= 0) {
					int v = 0;
					if (wallNorth) v |= 1;
					if (wallNorthWest) v |= 2;
					if (wallWest) v |= 4;
					v = shadows[v];
					if (v >= 0) {
						int below = blockAccess.get(coord.copyAndAdd(0, 1));
						int col = isWall(below);
						S soFar = s().style(spaceNumber, checkers).shadow(v);
						if (col>=0) {
							soFar.pips(true).col(col);
						}
						n = get(soFar);
					}
				}
				else {
					if (b != 0) {
						System.out.println(String.format("Something else: %s at %s", b, coord));
					}
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
