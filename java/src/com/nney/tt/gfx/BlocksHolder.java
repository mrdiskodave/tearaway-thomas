package com.nney.tt.gfx;

import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.List;

import org.lwjgl.BufferUtils;
import org.lwjgl.opengl.GL11;

import com.nney.tt.map.BlockAliasTable;
import com.nney.utils.Openable;

public class BlocksHolder {
	final private int blockSize;

	final private int gridSize;

	final private int gridCapacity;

	final private int blockCount;
	final private List<GlTexture> textures = new ArrayList<GlTexture>();

	private int listBase;
	
	public BlocksHolder(int blockSize, int gridSize, Openable blocksOpenable, BlockAliasTable invisibleBlockHiding) {
		this.blockSize = blockSize;
		this.gridSize = gridSize;
		this.gridCapacity = gridSize*gridSize;
		
		TemporaryBlockSource sbi = new TemporaryBlockSource(blocksOpenable, blockSize, blockSize);
		blockCount = sbi.getBlockCount();
		if (invisibleBlockHiding!=null) {
			for (int b=0; b<blockCount; b++) {
				sbi.hideBlock(invisibleBlockHiding.compress(b), b);
			}
		}
		
		int gridEdge = gridSize*blockSize;
		SimpleImage grid = SimpleImage.createEmpty(gridEdge, gridEdge);
		
		int gridPos = 0;
		for (int b=0; b<blockCount; b++) {
			int x = gridPos&gridSize-1;
			int y = gridPos/gridSize;
			x *= blockSize;
			y *= blockSize;
			grid.view(x, y, blockSize, blockSize).overwriteWith(sbi.getBlock(b));
			gridPos++;
			if (gridPos==gridCapacity) {
				textures.add(new GlTexture(grid));
				gridPos = 0;
			}
		}
		if (gridPos!=0) {
			System.out.println(String.format("last grid had %d/%d", gridPos, gridCapacity));
			textures.add(new GlTexture(grid));
		}
		
		preCompile();
	}

	private void preCompile() {
		listBase = GL11.glGenLists(blockCount);
		assert listBase!=0;
		
		for (int block=0; block<blockCount; block++) {
			GL11.glNewList(listBase+block, GL11.GL_COMPILE);
			idraw(block);
			GL11.glEndList();
		}
	}

	private void idraw(int x) {
		if (x!=0) {
			GlTexture t = textures.get(x / gridCapacity);
			x &= gridCapacity-1;
			int bx = x & gridSize-1;
			int by = x / gridSize;
			t.draw(0, 0, bx * blockSize, by * blockSize, blockSize, blockSize);
		}
		GL11.glTranslatef(blockSize, 0, 0);
	}
	
	public void draw(int[] blocks, int dx, int dy) {
		GL11.glPushMatrix();
		GL11.glTranslatef(dx, dy, 0);
		IntBuffer i = BufferUtils.createIntBuffer(blocks.length);
		i.put(blocks);
		i.rewind();
		GL11.glListBase(listBase);
		GL11.glCallLists(i);
		GL11.glPopMatrix();
	}
	
	public void drawOneSlowly(int block, int dx, int dy) {
		int[] blocks = new int[1];
		blocks[0] = block;
		draw(blocks, dx, dy);
	}
	
	public int getBlockCount() {
		return blockCount;
	}
	
	public void dispose() {
		for (GlTexture texture : textures) {
			texture.dispose();
		}
		GL11.glDeleteLists(listBase, blockCount);
	}
}
