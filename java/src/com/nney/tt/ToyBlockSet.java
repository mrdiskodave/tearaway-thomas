package com.nney.tt;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.map.GameMap;
import com.nney.tt.toygen.ToyGenerator;
import com.nney.tt.toygen.ToyLegacyCapture;
import com.nney.tt.toygen.ToyMaker;
import com.nney.tt.toygen.ToyMaker.Result;

public class ToyBlockSet extends BlockSet {
	private Result r;

	public ToyBlockSet(GraphicsContext gc, Config config) {
		ToyMaker tm = new ToyMaker();
		r = tm.generate();
		init(gc, config, r.hiding, r.blockInformation, r.blocks, r.masks, r.compression);
	}

	@Override
	public void expandMap(GameMap gameMap) {
		ToyGenerator t = new ToyGenerator(getBa(gameMap), r.where);
		t.run();
	}

	@Override
	public void legacyCapture(GameMap gameMap) {
		ToyLegacyCapture.capture(getBa(gameMap), r.where);
	}

	private BlockAccess getBa(final GameMap gameMap) {
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
				gameMap.setBlock(gameMap.move(c), b);
			}

			@Override
			public int get(Coord c) {
				return gameMap.safeGetBlock(gameMap.move(c));
			}
		};
		return ba;
	}

	@Override
	public LadderInformation getLadderInfo() {
		return null;
	}

}
