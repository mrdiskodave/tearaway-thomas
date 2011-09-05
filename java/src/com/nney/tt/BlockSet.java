package com.nney.tt;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.resources.TTResource;
import com.nney.utils.Openable;

public class BlockSet implements Disposable {
	final public Name name;
	final public BlocksHolder blocksHolder;
	final public MasksHolder maskHolder;
	final public WorldInformation wi;

	static class Name {
		final String worldName;
		final boolean configSeeMasks;
		final boolean configShowInvisible;

		Name(String worldName, boolean configSeeMasks, boolean configShowInvisible) {
			this.worldName = worldName;
			this.configSeeMasks = configSeeMasks;
			this.configShowInvisible = configShowInvisible;
		}
		
		@Override
		public String toString() {
			return String.format("%s-%s-%s", worldName, configSeeMasks, configShowInvisible);
		}
		
		@Override
		public boolean equals(Object obj) {
			Name that = (Name) obj;
			return toString().equals(that.toString());
		}
	}
	
	public BlockSet(GraphicsContext gc, Name name) {
		wi = WorldInformation.load(name.worldName);

		Openable blocksGraphics = TTResource.blocks(name.worldName);
		Openable masksGraphics = TTResource.blockMask(name.worldName);

		BlockSource bs = new BlockSource(name.configSeeMasks ? masksGraphics : blocksGraphics, Const.BLOCK_SIZE);
		if (!name.configShowInvisible) bs.doBlockHiding(wi.invisibleBlockHiding);
		blocksHolder = gc.createBlocksHolder(bs);
		maskHolder = new MasksHolder(Const.BLOCK_SIZE, masksGraphics);

		this.name = name;
	}


	@Override
	public void dispose() {
		blocksHolder.dispose();
	}
}
