package com.nney.tt.lwjgl;

import java.nio.IntBuffer;
import java.util.ArrayList;
import java.util.List;

import org.lwjgl.BufferUtils;
import org.lwjgl.opengl.GL11;

import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.SimpleImage;

public final class GlBlocksHolder implements BlocksHolder {
	final private int blockSize;

	static final private int GRID_SIZE = 8;

	static final private int GRID_CAPACITY = GRID_SIZE * GRID_SIZE;

	final private int blockCount;
	final private List<GlTexture> textures = new ArrayList<GlTexture>();

	private int listBase;

	public GlBlocksHolder(BlockSource sbi) {
		blockSize = sbi.getBlockSize();
		blockCount = sbi.getBlockCount();
		int gridEdge = GRID_SIZE * blockSize;
		SimpleImage grid = SimpleImage.createEmpty(gridEdge, gridEdge);

		int gridPos = 0;
		for (int b = 0; b < blockCount; b++) {
			int x = gridPos & GRID_SIZE - 1;
			int y = gridPos / GRID_SIZE;
			x *= blockSize;
			y *= blockSize;
			grid.view(x, y, blockSize, blockSize).overwriteWith(sbi.getBlock(b));
			gridPos++;
			if (gridPos == GRID_CAPACITY) {
				textures.add(new GlTexture(grid));
				gridPos = 0;
			}
		}
		if (gridPos != 0) {
			System.out.println(String.format("last grid had %d/%d", gridPos, GRID_CAPACITY));
			textures.add(new GlTexture(grid));
		}

		preCompile();
	}

	private void preCompile() {
		listBase = GL11.glGenLists(blockCount);
		assert listBase != 0;

		for (int block = 0; block < blockCount; block++) {
			GL11.glNewList(listBase + block, GL11.GL_COMPILE);
			idraw(block);
			GL11.glEndList();
		}
	}

	private void idraw(int x) {
		if (x != 0) {
			GlTexture t = textures.get(x / GRID_CAPACITY);
			x &= GRID_CAPACITY - 1;
			int bx = x & GRID_SIZE - 1;
			int by = x / GRID_SIZE;
			t.draw(0, 0, bx * blockSize, by * blockSize, blockSize, blockSize);
		}
		GL11.glTranslatef(blockSize, 0, 0);
	}

	@Override
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

	@Override
	public void draw(int block, int dx, int dy) {
		int[] blocks = new int[1];
		blocks[0] = block;
		draw(blocks, dx, dy);
	}

	@Override
	public int getBlockCount() {
		return blockCount;
	}

	@Override
	public void dispose() {
		for (GlTexture texture : textures) {
			texture.dispose();
		}
		GL11.glDeleteLists(listBase, blockCount);
	}
}
