package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.map.GameMap;
import com.nney.tt.toygen.ToyGenerator;
import com.nney.tt.toygen.ToyMaker;
import com.nney.tt.toygen.ToyMaker.Result;

public class ToyBlockSet extends BlockSet {
	private Result r;

	public ToyBlockSet(GraphicsContext gc, Config config) {
		ToyMaker tm = new ToyMaker();
		r = tm.generate();
		init(gc, config, r.hiding, r.blockInformation, r.blocks, r.masks);
	}

	@Override
	public int compressBlock(int currentBlock) {
		return currentBlock;
	}

	@Override
	public void expandMap(final GameMap gameMap) {
		BlockAccess ba = new BlockAccess() {
			@Override
			public int width() {
				return gameMap.width();
			}

			@Override
			public int height() {
				return gameMap.height();
			}

			@Override
			public void set(Coord c, int b) {
				gameMap.setBlock(c, b);
			}

			@Override
			public int get(Coord c) {
				return gameMap.safeGetBlock(c);
			}
		};
		ToyGenerator t = new ToyGenerator(ba, r.where);
		t.run();
	}

	@Override
	public LadderInformation getLadderInfo() {
		return null;
	}

}
