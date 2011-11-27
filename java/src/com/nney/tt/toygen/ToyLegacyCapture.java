package com.nney.tt.toygen;

import java.util.Map;

import com.nney.tt.BlockAccess;
import com.nney.tt.geom.Coord;

public class ToyLegacyCapture {
	public static void capture(BlockAccess blockAccess, Map<Integer, Integer> where) {
		for (int ly = 0; ly < blockAccess.height(); ly++) {
			for (int lx = 0; lx < blockAccess.width(); lx++) {
				Coord coord = new Coord(lx, ly);
				int b = blockAccess.get(coord);
				int x = b%20;
				int y = b/20;
				S out = null;
				if (y==0 && 1<=x && x<=4) {
					out = new S().wall(1);
				}
				else {
					if (4<= y&& y<12) {
						y -= 4;
						int v = 0;
						if (y>=4) v|=1;
						if (x>=7) v|=2;
						int[] space_table = { 0, 1, 2, 3 };
						out = new S().space(space_table[v]+1);
					}
				}
				if (out!=null) {
					Integer answer = where.get(out.flattern());
					assert answer != null;
					blockAccess.set(coord, answer);
				}
			}
		}
	}
}
