package com.nney.tt;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.gfx.SimpleImage.ChangePixel;
import com.nney.tt.map.BlockAliasTable;
import com.nney.tt.map.BlockInformation;
import com.nney.tt.map.GameMap;
import com.nney.tt.map.GameMap.BlockFunc;
import com.nney.tt.map.MasksHolder;

public abstract class BlockSet implements Disposable {
	private static final boolean CTC_EXCEPTIONAL_TOYLAND = true;
	
	static final private boolean CTC_CAN_HIDE = true;

	protected Config config;
	public BlocksHolder blocksHolder;
	public MasksHolder maskHolder;

	private BlockInformation blockInformation;

	public static class Config {
		final String worldName;
		final boolean seeMasks;
		final boolean showHidden;

		public Config(String worldName, boolean seeMasks, boolean showHidden) {
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
	
	
	public void init(GraphicsContext gc, Config config, BlockAliasTable hiddenHiding, BlockInformation blockInformation, SimpleImage bsi, SimpleImage msi) {
		this.blockInformation = blockInformation;
		
		if (config.seeMasks) {
			bsi = msi.copy();
			bsi.changePixels(new ChangePixel() {
				@Override
				public int change(int col) {
					// the same test that is in MasksHolder:
					if (col == 0xff000000) {
						// how we want to display ground?
						return 0xff000000;
					}
					// how we want to display sky?
					return 0;
				}
			});
		}

		BlockSource bs = new BlockSource(bsi, Const.BLOCK_SIZE);
		if (CTC_CAN_HIDE) {
		if (!config.showHidden) {
				if (hiddenHiding != null) {
				for (int b = 0; b < bs.getBlockCount(); b++) {
					bs.hideBlock(hiddenHiding.compress(b), b);
				}
			}
		}
		}
		
		this.blocksHolder = gc.createBlocksHolder(bs);
		this.maskHolder = new MasksHolder(msi);
		this.config = config;
	}


	@Override
	public void dispose() {
		blocksHolder.dispose();
	}

	public boolean isSame(Config config2) {
		return config.equals(config2);
	}
	
	public int getBlockCount() {
		return blocksHolder.getBlockCount();
	}

	public void draw(int b, int x, int y) {
		blocksHolder.draw(b, x, y);
	}

	public String getBlockInfo(int block) {
		return blockInformation.get(block);
	}

	public void compressMap(GameMap gameMap) {
		BlockFunc f = new BlockFunc() {
			@Override
			public int update(int x) {
				return compressBlock(x);
			}
		};
		gameMap.apply(f);
	}

	
	abstract public int compressBlock(int currentBlock);
	abstract public void expandMap(GameMap gameMap);
	abstract public LadderInformation getLadderInfo();


	public static BlockSet createBlockSet(GraphicsContext gc, Config c) {
		if (CTC_EXCEPTIONAL_TOYLAND) {
			if (c.worldName.equals("t")) {
				return new ToyBlockSet(gc, c);
			}
		}
		return new RegularBlockSet(gc, c);
	}


	public void legacyCapture(GameMap gameMap) {
		
	}

}
