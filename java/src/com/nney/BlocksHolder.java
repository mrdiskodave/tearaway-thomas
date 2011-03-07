package com.nney;

import java.util.ArrayList;
import java.util.List;

import com.nney.utils.Openable;

public class BlocksHolder {
	final private int blockSize;

	final private int gridSize;

	final private int gridCapacity;

	final private int blockSizeShift;
	final private int gridSizeShift;

	final private int gridCapShift;

	final private int blockCount;
	final private Texture[] textures;
	
	public BlocksHolder(int blockSize, int gridSize, Openable blocksOpenable) {
		this.blockSize = blockSize;
		this.gridSize = gridSize;
		this.gridCapacity = gridSize*gridSize;
		blockSizeShift = discoverShift(blockSize);
		gridSizeShift = discoverShift(gridSize);
		gridCapShift = discoverShift(gridCapacity);
		
		List<Texture> textures = new ArrayList<Texture>();
		 
		TemporaryBlockSource sbi = new TemporaryBlockSource(blocksOpenable, blockSize);
		blockCount = sbi.getBlockCount();
		
		int gridEdge = gridSize*blockSize;
		SimpleImage grid = SimpleImage.createEmpty(gridEdge, gridEdge);
		
		int gridPos = 0;
		for (int b=0; b<sbi.getBlockCount(); b++) {
			int x = gridPos&gridSize-1;
			int y = gridPos/gridSize;
			x *= blockSize;
			y *= blockSize;
			grid.view(x, y, blockSize, blockSize).overwriteWith(sbi.getBlock(b));
			gridPos++;
			if (gridPos==gridCapacity) {
				textures.add(new Texture(grid));
				gridPos = 0;
			}
		}
		if (gridPos!=0) {
			System.out.println(String.format("last grid had %d/%d", gridPos, gridCapacity));
			textures.add(new Texture(grid));
		}
		this.textures = (Texture[]) textures.toArray(new Texture[textures.size()]);
	}
	
	static private int discoverShift(int v) {
		for (int x=0; x<32; x++) {
			int a = 1<<x;
			if (a==v) return x;
		}
		assert false : v;
		return 0;
	}

	public void draw(int block, int dx, int dy) {
		Texture t = textures[block >> gridCapShift];
		block &= gridCapacity-1;
		int bx = block & gridSize-1;
		int by = block >> gridSizeShift;
		t.draw(dx, dy, bx << blockSizeShift, by << blockSizeShift, blockSize, blockSize);
	}
	
	public int getBlockCount() {
		return blockCount;
	}
}
