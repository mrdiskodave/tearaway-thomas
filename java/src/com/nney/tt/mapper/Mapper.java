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
	private static final int BLOCK_CHOOSING_BG = 0x0020ff;
	private static final int BLOCKS_PER_LINE = 20;
	private static final int SELECTION_BLOCK_COLOUR = 0xff0000;
	private static final int MAPPER_CURRENT_BLOCK_COLOUR = 0xffff00;

	private int showTimer;
	private int currentBlock;

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
	private UndoControler undoControler = new UndoControler();
	private DrawingTool drawingTool;

	private MM mode = new DrawTool();

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, World parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.gc = gc;
		this.blocksHolder = blocksHolder;
		this.debugFont = debugFont;
		this.drawingTool = new DrawingTool(gameMap);
		blockCount = blocksHolder.getBlockCount();
		blockPaletteHeight = Math2.roundUpDiv(blockCount, BLOCKS_PER_LINE);
		mapperGC = new MapperGC(gc);
	}

	private final class BlockChooser extends MM {
		@Override
		boolean ownScreen() {
			return true;
		}

		@Override
		String name() {
			return "chooser";
		}

		@Override
		void run() {
			blockChoosingMode();
			showBlocks();
		}
	}

	private final class DrawTool extends MM {
		@Override
		String name() {
			return "draw";
		}

		@Override
		void run() {
			drawingLMB();
		}
	}

	private final class TrackerTool extends MM {
		Coord drawPos = computeMousePos();

		@Override
		public void run() {
			showBlocks();
			if (drawPos != null) {
				Coord oldBlock = drawPos.copy();
				oldBlock.div(Const.BLOCK_SIZE);
				Coord newBlock = computeMousePos();
				newBlock.div(Const.BLOCK_SIZE);
				newBlock.sub(oldBlock);
				changeCurrentBlock(newBlock.x + newBlock.y * BLOCKS_PER_LINE);
			}
			drawPos = computeMousePos();
			drawingLMB();
		}

		@Override
		String name() {
			return "track";
		}
	}

	private final class HandTool extends MM {
		Coord dragPos = computeMousePos();

		@Override
		public void run() {
			if (dragPos !=null && mouse.isDown(Pointer.KEY_LEFT)) {
				Coord delta = dragPos.copy();
				delta.sub(computeMousePos());
				if (keyboard.isDown(Keyboard.KEY_LSHIFT)) {
					delta.mul(2);
				}
				if (keyboard.isDown(Keyboard.KEY_LCONTROL)) {
					delta.mul(4);
				}
				parent.moveScreen(delta);
			}
			dragPos = computeMousePos();
		}

		@Override
		String name() {
			return "hand";
		}
	}

	private final class EyeDropperTool extends MM {
		@Override
		String name() {
			return "eyedropper";
		}

		@Override
		void run() {
			showBlocks();
			if (mouse.isDown(Pointer.KEY_LEFT)) {
				currentBlock = gameMap.getBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE));
			}
			keyboardBlockChoiceShown();
		}
	}

	abstract class MM {
		abstract String name();
		boolean ownScreen() { return false; }
		void run() {};
		void stop() {};
	}
	
		
	
	public void run() {
		
		if (!mode.ownScreen()) {
			gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0x0080ff);
			parent.drawMap();

			Coord mousePos = computeMousePos();
			{
				Coord box = mousePos.copy();
				box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
				box.sub(parent.getScreenPosition());
				mapperGC.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, 0xff0000);
			}
	
	
			if (showTimer != 0) {
				showTimer--;
				int d = 5;
				int x = Math2.limit(0, BLOCKS_PER_LINE - d, (currentBlock % BLOCKS_PER_LINE) - (d/2));
				int y = Math2.limit(0, blockPaletteHeight - d, (currentBlock / BLOCKS_PER_LINE - (d/2)));
				int db = Const.BLOCK_SIZE * d;
				int sx = gc.screenWidth()-db;
				int sy = 0;
				gc.fillRectangle(sx, sy, db, db, BLOCK_CHOOSING_BG);
				for (BlockPos p : blockList(x, y, d, d, sx, sy)) {
					blocksHolder.draw(p.b, p.x, p.y);
					if (currentBlock == p.b) {
						mapperGC.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, MAPPER_CURRENT_BLOCK_COLOUR);
					}
				}
	
			}
		}

		
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_TAB:
			parent.quitMapper(computeMousePos());
			return;
		case Keyboard.KEY_I:
			chageMM(new EyeDropperTool());
			return;
		case Keyboard.KEY_H:
			chageMM(new HandTool());
			return;
		case Keyboard.KEY_D:
			chageMM(new DrawTool());
			return;
		case Keyboard.KEY_F:
			chageMM(new TrackerTool());
			return;
		case Keyboard.KEY_C:
			chageMM(new BlockChooser());
			return;
		}
		
		sayIt(mode.name());
		mode.run();
		
		if (!mode.ownScreen()) {
			undoRedo();
		}

	}



	private void sayIt(String string) {
		int x = 10;
		int y = 10;
		debugFont.draw(x, y, 0xffffff, 0, string);
	}



	private void chageMM(MM mm) {
		mode.stop();
		mode = mm;
	}



	private void undoRedo() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_U:
			undoControler.undo();
			break;
		case Keyboard.KEY_R:
			undoControler.redo();
			break;
		}
	}



	private void drawingLMB() {
		// Drawing with the left button
		if (mouse.isDown(Pointer.KEY_LEFT)) {
			drawingTool.setBlock(computeMousePos().copyAndDiv(Const.BLOCK_SIZE), currentBlock);
		}
		else {
			undoControler.addUndo(drawingTool.endEdit());
		}
		keyboardBlockChoiceShown();
	}



	private void keyboardBlockChoiceShown() {
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
			currentBlock = 0;
			return true;
		case Keyboard.KEY_UP:
			changeCurrentBlock(-BLOCKS_PER_LINE);
			return true;
		case Keyboard.KEY_DOWN:
			changeCurrentBlock(BLOCKS_PER_LINE);
			return true;
		case Keyboard.KEY_LEFT:
			changeCurrentBlock(-1);
			return true;
		case Keyboard.KEY_RIGHT:
			changeCurrentBlock(1);
			return true;
		}
		return false;
	}

	private void changeCurrentBlock(int delta) {
		int b = delta +  currentBlock;
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		currentBlock = b;
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
		gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), BLOCK_CHOOSING_BG);

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
			if (currentBlock == p.b) {
				mapperGC.drawBox(p.x, p.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, MAPPER_CURRENT_BLOCK_COLOUR);
				debugFont.draw(BLOCKS_PER_LINE * Const.BLOCK_SIZE, p.y, MAPPER_CURRENT_BLOCK_COLOUR, 0,
						String.format("%4d", currentBlock));
			}
			if (my >= p.y && my <= p.y + 15 && mx >= p.x && mx <= p.x + 15) {
				hoverBlock = p.b;
				if (hoverBlock == currentBlock) {
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
			currentBlock = hoverBlock;
		}
	}

	private List<BlockPos> blockList(int sx, int sy, int width, int height, int mdx, int mdy) {
		List<BlockPos> answer = new ArrayList<BlockPos>();
		for (int by = 0; by < height; by++) {
			for (int bx = 0; bx < width; bx++) {
				int b = (sy + by) * BLOCKS_PER_LINE + (sx + bx);
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
