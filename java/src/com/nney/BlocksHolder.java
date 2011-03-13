package com.nney;

import java.util.ArrayList;
import java.util.List;

import org.lwjgl.opengl.GL11;

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

	private int listBase;
	
	public BlocksHolder(int blockSize, int gridSize, Openable blocksOpenable) {
		this.blockSize = blockSize;
		this.gridSize = gridSize;
		this.gridCapacity = gridSize*gridSize;
		blockSizeShift = GlTools.discoverShift(blockSize);
		gridSizeShift = GlTools.discoverShift(gridSize);
		gridCapShift = GlTools.discoverShift(gridCapacity);
		
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
		
		preCompile();
	}

	private void preCompile() {
		listBase = GL11.glGenLists(blockCount);
		assert listBase!=0;
		
		for (int x=0; x<blockCount; x++) {
			GL11.glNewList(listBase+x, GL11.GL_COMPILE);
			idraw(x, 0, 0);
			GL11.glEndList();
		}
	}
	


	private void idraw(int block, int dx, int dy) {
		assert block>=0;
		assert block<blockCount;
		Texture t = textures[block >> gridCapShift];
		block &= gridCapacity-1;
		int bx = block & gridSize-1;
		int by = block >> gridSizeShift;
		t.draw(dx, dy, bx << blockSizeShift, by << blockSizeShift, blockSize, blockSize);
	}
	
	public void draw(int block, int dx, int dy) {
		assert block>=0;
		assert block<blockCount;
		GL11.glPushMatrix();
		GL11.glTranslatef(dx, dy, 0);
		GL11.glCallList(listBase+block);
		GL11.glPopMatrix();
	}
	
	public int getBlockCount() {
		return blockCount;
	}
}
