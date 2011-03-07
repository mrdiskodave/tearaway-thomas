package com.nney;

import java.util.ArrayList;
import java.util.List;

public class BlocksHolder {
	final private List<Texture> textures = new ArrayList<Texture>();

	final private int blockSize;

	final private int gridSize;

	final private int gridCap;

	final private int blockSizeShift;
	final private int gridSizeShift;

	final private int gridCapShift;

	private int blockCount;
	
	public BlocksHolder(int blockSize, int gridSize) {
		this.blockSize = blockSize;
		this.gridSize = gridSize;
		this.gridCap = gridSize*gridSize;
		blockSizeShift = discoverShift(blockSize);
		gridSizeShift = discoverShift(gridSize);
		gridCapShift = discoverShift(gridCap);
	}
	
	static private int discoverShift(int v) {
		for (int x=0; x<32; x++) {
			int a = 1<<x;
			if (a==v) return x;
		}
		assert false : v;
		return 0;
	}
	
	public void load() {
		SrcBlockImg sbi = new SrcBlockImg(blockSize);
		blockCount = sbi.getBlockCount();
		
		int pos = 0;
		int palEdge = gridSize*blockSize;
		SimpleImage pal = SimpleImage.createEmpty(palEdge, palEdge);
		
		for (int b=0; b<sbi.getBlockCount(); b++) {
			int x = pos&gridSize-1;
			int y = pos/gridSize;
			x *= blockSize;
			y *= blockSize;
			pal.view(x, y, blockSize, blockSize).overwriteWith(sbi.getBlock(b));
			pos++;
			if (pos==gridCap) {
				ship(pal, pos);
				pos = 0;
			}
		}
		if (pos!=0) {
			ship(pal, pos);
		}
	}

	private void ship(SimpleImage pal, int pos) {
		System.out.println("ship it "+Integer.toString(pos));
		textures.add(new Texture(pal));
	}
	
	public void draw(int block, int dx, int dy) {
		Texture t = textures.get(block >> gridCapShift);
		block &= gridCap-1;
		int bx = block & gridSize-1;
		int by = block >> gridSizeShift;
		t.draw(dx, dy, bx << blockSizeShift, by << blockSizeShift, blockSize, blockSize);
	}
	
	public int getBlockCount() {
		return blockCount;
	}
}
