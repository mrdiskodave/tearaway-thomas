package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.Const;
import com.nney.tt.World;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.map.GameMap;
import com.nney.utils.Math2;

public class Mapper {
	private static final int BLOCKS_PER_LINE = 20;
	private static final int SELECTION_BLOCK_COLOUR = 0xff0000;
	private static final int MAPPER_CURRENT_BLOCK_COLOUR = 0xffff00;

	private Coord dragPos;
	private int showTimer;
	private Coord drawPos;
	private int chosenBlock;

	final private int blockPaletteHeight;
	final private int blockCount;
	final private MapperGC mapperGC;
	final private GraphicsContext gc;
	final private BlocksHolder blocksHolder;
	final private Pointer mouse;
	final private Keyboard keyboard;
	private final World parent;
	private final Font debugFont;
	private final GameMap gameMap;

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, World parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc, BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.gc = gc;
		this.blocksHolder = blocksHolder;
		this.debugFont = debugFont;
		blockCount = blocksHolder.getBlockCount(); 
		blockPaletteHeight = Math2.roundUpDiv(blockCount, BLOCKS_PER_LINE);
		mapperGC = new MapperGC(gc);
	}
	
	public void run() {
		// block selection
		if (mouse.isDown(Pointer.KEY_RIGHT)) {
			blockChoosingMode();
			showBlocks();
			return;
		}

		parent.drawMap();
		
		Coord mousePos = computeMousePos();
		{
			Coord box = mousePos.copy();
			box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
			box.sub(parent.getScreenPosition());
			mapperGC.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, 0xff0000);
		}
		
		if (showTimer!=0) {
			showTimer--;
			
			int x = Math2.limit(0, BLOCKS_PER_LINE-5, (chosenBlock % BLOCKS_PER_LINE)-2);
			int y = Math2.limit(0, blockPaletteHeight-5, (chosenBlock / BLOCKS_PER_LINE-2));
			gc.fillRectangle(0, 0, Const.BLOCK_SIZE*5, Const.BLOCK_SIZE*5, 0x0080ff);
			for (BlockPos p : blockList(x, y, 5, 5, 0, 0)) {
				blocksHolder.draw(p.b, p.x, p.y);
				if (chosenBlock == p.b) {
					mapperGC.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, MAPPER_CURRENT_BLOCK_COLOUR);
				}
			}

		}

		switch (keyboard.justPressed()) {
		case Keyboard.KEY_TAB:
			parent.quitMapper(mousePos);
			return;
		case Keyboard.KEY_I:
			chosenBlock = gameMap.getBlock2(mousePos);
			showBlocks();
			return;
		}

		if (keyboard.isDown(Keyboard.KEY_SPACE)) {
			Coord delta = dragPos;
			if (delta != null && mouse.isDown(Pointer.KEY_LEFT)) {
				delta.sub(mousePos);
				if (keyboard.isDown(Keyboard.KEY_LSHIFT)) {
					delta.mul(2);
				}
				parent.moveScreen(delta);
			}
			dragPos = computeMousePos();
			return;
		}
		dragPos = null;
		
		if (keyboard.isDown(Keyboard.KEY_D)) {
			showBlocks();
			if (drawPos != null && mouse.isDown(Pointer.KEY_LEFT)) {
				Coord oldBlock = drawPos.copy();
				oldBlock.div(Const.BLOCK_SIZE);
				Coord newBlock = mousePos.copy();
				newBlock.div(Const.BLOCK_SIZE);
				newBlock.sub(oldBlock);
				moveChosenBlock(newBlock.x+newBlock.y*BLOCKS_PER_LINE);
				gameMap.setBlock2(mousePos, chosenBlock);
			}
			drawPos = computeMousePos();
			return;
		}
		drawPos = null;

		if (mouse.isDown(Pointer.KEY_LEFT)) {
			gameMap.setBlock2(mousePos, chosenBlock);
			return;
		}

		if (keyboardBlockChoice()) {
			showBlocks();
		}
	}

	private void showBlocks() {
		showTimer = 100;
	}

	private boolean keyboardBlockChoice() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_0:
			chosenBlock = 0;
			return true;
		case Keyboard.KEY_UP:
			return moveChosenBlock(-BLOCKS_PER_LINE);
		case Keyboard.KEY_DOWN:
			return moveChosenBlock(BLOCKS_PER_LINE);
		case Keyboard.KEY_LEFT:
			return moveChosenBlock(-1);
		case Keyboard.KEY_RIGHT:
			return moveChosenBlock(1);
		}
		return false;
	}

	private boolean moveChosenBlock(int i) {
		i += chosenBlock;
		if (i<0) {
			i += blockCount;
		}
		if (i>=blockCount) {
			i -= blockCount;
		}
		chosenBlock = i;
		return true;
	}

	private Coord computeMousePos() {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		mp.add(parent.getScreenPosition()); 
		return mp;
	}

	private class BlockPos {
		public final int x;
		public final int y;
		public final int b;

		BlockPos(int x, int y, int b) {
			this.x = x;
			this.y = y;
			this.b = b;
		}
	}

	private void blockChoosingMode() {
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0x0080ff);

		keyboardBlockChoice();

		int mx = mouse.getX();
		int my = mouse.getY();
		// System.out.println(String.format("%d,%d", mx, my));
		// drawSight(mx, my, 20, 0xff0000);

		int protrusion = Math.max(blockPaletteHeight * Const.BLOCK_SIZE - gc.screenHeight(), 0);
		int mdy = 0;
		if (protrusion != 0) {
			int mid = 64;
			int big = gc.screenHeight() - 1 - mid * 2;
			int z = Math.min(Math.max(0, my - mid), big);
			mdy = (protrusion * z) / -big;
		}
		int hoverBlock = -1;

		for (BlockPos p : blockList(0, 0, BLOCKS_PER_LINE, blockPaletteHeight, 0, mdy)) {
			blocksHolder.draw(p.b, p.x, p.y);
			if (chosenBlock == p.b) {
				mapperGC.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, MAPPER_CURRENT_BLOCK_COLOUR);
				debugFont.draw(BLOCKS_PER_LINE * Const.BLOCK_SIZE, p.y, MAPPER_CURRENT_BLOCK_COLOUR, 0,
						String.format("%4d", chosenBlock));
			}
			if (my >= p.y && my <= p.y + 15 && mx >= p.x && mx <= p.x + 15) {
				hoverBlock = p.b;
				if (hoverBlock == chosenBlock) {
					mapperGC.drawBox(p.x + 1, p.y + 1, 14, 14, SELECTION_BLOCK_COLOUR);
				}
				else {
					mapperGC.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, SELECTION_BLOCK_COLOUR);
				}
				debugFont.draw(BLOCKS_PER_LINE * Const.BLOCK_SIZE + 8 * 4, p.y, SELECTION_BLOCK_COLOUR, 0,
						String.format("%4d", hoverBlock));
			}
		}
		if (mouse.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			chosenBlock = hoverBlock;
		}
	}

	private List<BlockPos> blockList(int sx, int sy, int width, int height, int mdx, int mdy) {
		List<BlockPos> answer = new ArrayList<BlockPos>();
		for (int by = 0; by < height; by++) {
			for (int bx = 0; bx < width; bx++) {
				int b = (sy+by) * BLOCKS_PER_LINE + (sx+bx);
				if (b < blockCount) {
					int x = bx * Const.BLOCK_SIZE + mdx;
					int y = by * Const.BLOCK_SIZE + mdy;
					answer.add(new BlockPos(x, y, b));
				}
			}
		}
		return answer;
	}
}
