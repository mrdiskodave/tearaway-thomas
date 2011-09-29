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
	final public String worldName;
	final public BlocksHolder blocksHolder;
	final public MasksHolder maskHolder;
	final public WorldInformation wi;

	public static class Config {
		final private boolean seeMasks;
		final private boolean showHidden;

		public Config(boolean seeMasks, boolean showHidden) {
			this.seeMasks = seeMasks;
			this.showHidden = showHidden;
		}
	}
	
	
	public BlockSet(GraphicsContext gc, String worldName, Config config) {
		wi = WorldInformation.load(worldName);

		SimpleImage msi = new SimpleImage(OpenableTools.mustLoad(TTResource.blockMask(worldName)));
		
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
			bsi = new SimpleImage(OpenableTools.mustLoad(TTResource.blocks(worldName)));
		}

		BlockSource bs = new BlockSource(bsi, Const.BLOCK_SIZE);
		if (!config.showHidden) bs.doBlockHiding(wi.invisibleBlockHiding);
		blocksHolder = gc.createBlocksHolder(bs);
		maskHolder = new MasksHolder(Const.BLOCK_SIZE, msi);

		this.worldName = worldName;
	}


	@Override
	public void dispose() {
		blocksHolder.dispose();
	}
}
