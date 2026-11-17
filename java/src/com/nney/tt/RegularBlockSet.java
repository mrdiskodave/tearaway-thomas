package com.nney.tt;

import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.map.GameMap;
import com.nney.tt.resources.TTResource;
import com.nney.utils.OpenableTools;

public class RegularBlockSet extends BlockSet {
	private WorldInformation wi;

	public RegularBlockSet(GraphicsContext gc, Config config) {
		System.out.println("Creating BlockSet " + config);
		wi = WorldInformation.load(config.worldName);

		SimpleImage bsi = new SimpleImage(OpenableTools.mustLoad(TTResource.blocks(config.worldName)));
		SimpleImage msi = new SimpleImage(OpenableTools.mustLoad(TTResource.blockMask(config.worldName)));

		init(gc, config, wi.invisibleBlockHiding, wi.blockInformation, bsi, msi, wi.blockRandomisationTable);
	}

	@Override
	public void expandMap(GameMap gameMap) {
		gameMap.apply(x -> wi.blockRandomisationTable.shuffle(x));
	}

	@Override
	public LadderInformation getLadderInfo() {
		return wi.ladderInformation;
	}
}