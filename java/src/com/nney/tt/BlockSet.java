package com.nney.tt;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;
import com.nney.tt.map.MasksHolder;
import com.nney.tt.resources.TTResource;
import com.nney.utils.OpenableTools;

public class BlockSet implements Disposable {
	public Config config;
	public BlocksHolder blocksHolder;
	public MasksHolder maskHolder;
	public WorldInformation wi;

	static class Config {
		final String worldName;
		final boolean seeMasks;
		final boolean showHidden;

		Config(String worldName, boolean seeMasks, boolean showHidden) {
			this.worldName = worldName;
			this.seeMasks = seeMasks;
			this.showHidden = showHidden;
		}
		
		@Override
		public String toString() {
			return String.format("%s-%s-%s", worldName, seeMasks, showHidden);
		}
		
		@Override
		public boolean equals(Object obj) {
			Config that = (Config) obj;
			return toString().equals(that.toString());
		}
	}
	
	public BlockSet(GraphicsContext gc, Config config) {
		wi = WorldInformation.load(config.worldName);

		SimpleImage msi = new SimpleImage(OpenableTools.mustLoad(TTResource.blockMask(config.worldName)));
		
		SimpleImage bsi;
		if (config.seeMasks) {
			bsi = msi.copy();
			bsi.changePixels(new ChangePixel() {
				@Override
				public int change(int col) {
					// the same test that is in MasksHolder:
					if (col==0xff000000) { 
						// how we want to display ground?
						return 0xff000000; 
					}
					// how we want to display sky?
					return 0; 
				}
			});
		}
		else {
			bsi = new SimpleImage(OpenableTools.mustLoad(TTResource.blocks(config.worldName)));
		}

		BlockSource bs = new BlockSource(bsi, Const.BLOCK_SIZE);
		if (!config.showHidden) bs.doBlockHiding(wi.invisibleBlockHiding);
		blocksHolder = gc.createBlocksHolder(bs);
		maskHolder = new MasksHolder(Const.BLOCK_SIZE, msi);

		this.config = config;
	}


	@Override
	public void dispose() {
		blocksHolder.dispose();
	}
}