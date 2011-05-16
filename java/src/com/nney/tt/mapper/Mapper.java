package com.nney.tt.mapper;

import java.lang.reflect.Field;
import java.util.Map.Entry;

import com.nney.tt.Const;
import com.nney.tt.MapperServices;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienProp;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.geom.XRange;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.UnifiedKeyTester;
import com.nney.tt.map.GameMap;

public class Mapper implements PenServices {
	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	private static final int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int showTimer;
	private int currentBlock;
	final private int blockCount;
	private BlockPalette bp;

	final private MapperGC mgc;
	final private Pointer mouse;
	final private Keyboard keyboard;
	private final MapperServices parent;
	private final GameMap gameMap;

	private UndoControler undoControler = new UndoControler();
	private ColorCycler colorCycler = new ColorCycler();
	final private UnifiedKeyTester ukt;

	private Tool chooserTool = new ChooserTool();
	private Tool drawTool = new GeneralTool(this, Cursor.BLOCK, "draw", new BlockTrackingPen(), new DrawingPen());
	private Tool eyeDropperTool = new GeneralTool(this, Cursor.BLOCK, "eyeDropper", new EyeDropperPen());
	private Tool handTool = new GeneralTool(this, Cursor.NONE, "hand", new HandPen());
	private Tool alienTool = new GeneralTool(this, Cursor.NONE, "alien", new AlienSelectionPen());

	private Tool tool;
	private Tool otherTool;

	private int keyThatSustainsTheOtherTool;

	private EditConsolidator edit;

	private Alien selectedAlien;

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(GameMap gameMap, MapperServices parent, Pointer mouse, Keyboard keyboard, GraphicsContext gc,
			BlocksHolder blocksHolder, Font debugFont) {
		this.gameMap = gameMap;
		this.parent = parent;
		this.mouse = mouse;
		this.keyboard = keyboard;
		this.ukt = new UnifiedKeyTester(mouse, keyboard);
		blockCount = blocksHolder.getBlockCount();
		mgc = new MapperGC(gc, debugFont);
		bp = new BlockPalette(colorCycler, mgc, blocksHolder);
		tool = drawTool;
	}

	private final class ChooserTool extends Tool {
		@Override
		boolean ownScreen() {
			return true;
		}

		@Override
		void run() {
			blockChoosingMode();
			showBlocks();
		}
	}

	private final class GeneralTool extends Tool {
		private final Pen[] pens;
		private final String name;
		private final Cursor cursor;

		GeneralTool(PenServices srv, Cursor cursor, String name, Pen... pens) {
			for (Pen pen : pens) {
				pen.srv = srv;
			}
			this.cursor = cursor;
			this.name = name;
			this.pens = pens;
		}

		@Override
		void presentation() {
			for (Pen pen : pens) {
				pen.always();
			}
		}
		
		@Override
		public void run() {
			if (isFree()) {
				for (Entry<Integer, Tool> e : nest.entrySet()) {
					if (ukt.isDown(e.getKey())) {
						pushTool(e.getKey(), e.getValue());
					}
				}
			}
			if (cursor == Cursor.BLOCK) {
				drawBlockCursor();
			}
			for (Pen pen : pens) {
				Coord m = computeMousePos(pen.usesWorldCoords());
				boolean pressed = ukt.isDown(pen.key());
				if (pen.active) {
					if (pressed) {
						pen.stroke(m.copy());
					}
					else {
						pen.up(m.copy());
						pen.active = false;
						lessBusy();
					}
				}
				else {
					if (pressed) {
						pen.down(m.copy());
						pen.active = true;
						moreBusy();
					}
				}

			}
		}

		@Override
		String name() {
			return name;
		}
	}

	public void run() {
		colorCycler.advance();

		if (!tool.ownScreen()) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			parent.drawMap();
			parent.mapperDrawAliens();
		}

		switch (keyboard.justPressed()) {
		case Keyboard.KEY_TAB:
			parent.quitMapper(computeMousePos(true));
			return;
		case Keyboard.KEY_I:
			tool = eyeDropperTool;
			return;
		case Keyboard.KEY_H:
			tool = handTool;
			return;
		case Keyboard.KEY_D:
			tool = drawTool;
			return;
		case Keyboard.KEY_C:
			tool = chooserTool;
			return;
		case Keyboard.KEY_A:
			tool = alienTool;
			return;
		}

		drawTool.addNested(Keyboard.KEY_SPACE, handTool);
		drawTool.addNested(Pointer.KEY_RIGHT, chooserTool);
		eyeDropperTool.addNested(Keyboard.KEY_SPACE, handTool);
		alienTool.addNested(Keyboard.KEY_SPACE, handTool);

		Tool t = tool;
		if (otherTool != null) {
			if (otherTool.isFree() && !ukt.isDown(keyThatSustainsTheOtherTool)) {
				otherTool = null;
			}
			else {
				t = otherTool;
			}
		}

		t.presentation();
		if (t==otherTool) {
			tool.presentation();
		}
		t.run();

		if (!t.ownScreen()) {
			sayIt(t.name());
			if (showTimer != 0) {
				showTimer--;
				bp.showSmallPalette(currentBlock);
			}
			undoRedo();
		}
	}

	private void drawBlockCursor() {
		Coord mousePos = computeMousePos(true);
		Coord box = mousePos.copy();
		box.and(-Const.BLOCK_SIZE, -Const.BLOCK_SIZE);
		box.sub(parent.getScreenPosition());
		mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, colorCycler.process(COL_CURRENT_BLOCK));
	}

	private void sayIt(String s) {
		if (s != null) mgc.drawText(10, 10, 0xffffff, s);
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

	@Override
	public void keyboardBlockChoiceAndShow() {
		keyboardBlockChoice();
	}

	private boolean keyboardBlockChoice() {
		switch (keyboard.justPressed()) {
		case Keyboard.KEY_0:
			currentBlock = 0;
			return true;
		case Keyboard.KEY_UP:
			changeCurrentBlock(0, -1);
			return true;
		case Keyboard.KEY_DOWN:
			changeCurrentBlock(0, 1);
			return true;
		case Keyboard.KEY_LEFT:
			changeCurrentBlock(-1, 0);
			return true;
		case Keyboard.KEY_RIGHT:
			changeCurrentBlock(1, 0);
			return true;
		}
		return false;
	}

	private Coord computeMousePos(boolean world) {
		Coord mp = new Coord(mouse.getX(), mouse.getY());
		if (world) mp.add(parent.getScreenPosition());
		return mp;
	}

	private void blockChoosingMode() {
		keyboardBlockChoice();
		int mx = mouse.getX();
		int my = mouse.getY();

		// System.out.println(String.format("%d,%d", mx, my));
		// drawSight(mx, my, 20, 0xff0000);

		int hoverBlock = bp.showBigPalette(currentBlock, mx, my);
		if (ukt.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			currentBlock = hoverBlock;
		}
	}

	@Override
	public void changeCurrentBlock(int dx, int dy) {
		int delta = bp.getPaletteDelta(dx, dy);
		int b = delta + currentBlock;
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		currentBlock = b;
		showBlocks();
	}

	@Override
	public void showBlocks() {
		showTimer = 100;
	}

	@Override
	public EditConsolidator startEdit() {
		System.out.println("Start edit");
		assert edit == null;
		edit = new EditConsolidator(gameMap);
		return edit;
	}

	@Override
	public void endEdit() {
		System.out.println("Submit edit");
		assert edit != null;
		undoControler.addUndo(edit.endEdit());
		edit = null;
	}

	@Override
	public int getCurrentBlock() {
		return currentBlock;
	}

	@Override
	public void setCurrentBlockFromMap(Coord c) {
		currentBlock = gameMap.getBlock(c);
	}

	@Override
	public void scroll(Coord delta) {
		if (ukt.isDown(Keyboard.KEY_LSHIFT)) {
			delta.mul(2);
		}
		if (ukt.isDown(Keyboard.KEY_LCONTROL)) {
			delta.mul(4);
		}
		parent.moveScreen(delta);
	}

	private void pushTool(int key, Tool tool) {
		keyThatSustainsTheOtherTool = key;
		otherTool = tool;
	}

	// --------------------------------------------------

	public boolean haveAlien() {
		if (selectedAlien != null && !selectedAlien.remove) {
			return true;
		}
		selectedAlien = null; // just to help with garbage collection
		return false;
	}

	@Override
	public void selectNearestAlien(Coord c) {
		selectedAlien = parent.findNearestAlien(c);
	}

	@Override
	public void showSelectedAlienProps() {
		if (haveAlien()) {
			Coord sac = selectedAlien.c.copy();
			sac.sub(parent.getScreenPosition());
			mgc.drawSight(sac.x, sac.y, 7, colorCycler.process(0xff00ffff));

			System.out.println("---");
			Field[] fs = selectedAlien.getClass().getFields();
			for (Field f : fs) {
				AlienProp z = f.getAnnotation(AlienProp.class);
				if (z != null) {
					Object po = ksfg(f, selectedAlien);
					if (f.getType()==Box.class){ 
						Coord scr = parent.getScreenPosition();
						Box p = (Box) po;
						p = p.copy();
						p.sub(scr);
						System.out.println("Box:");

						boxPlease(p);
						controlPoint(p.left, p.top);
						controlPoint(p.right, p.bottom);
					}
					if (f.getType()==XRange.class){ 
						XRange p = (XRange) po;
						Coord scr = parent.getScreenPosition(); 
						Box box = new Box(p.left-scr.x, 0, p.right-scr.x, mgc.screenHeight()-1);
						System.out.println("Range:");
						boxPlease(box);
						controlPoint(box.left, sac.y);
						controlPoint(box.right, sac.y);
					}
					if (f.getType()==Coord.class) {
						Coord scr = parent.getScreenPosition(); 
						System.out.println("Ord:");
						Coord p = (Coord) po;
						p = p.copy();
						p.sub(scr);

						controlPoint(p.x, p.y);
					}
				}
			}
		}
	}

	private void controlPoint(int x, int y) {
		int i = 3;
		mgc.fillRectangle(x - i, y - i, i * 2+1, i * 2+1, 0xffffff00);
	}

	void boxPlease(Box box) {
		int x = box.left;
		int y = box.top;
		mgc.drawTransBox(x, y, box.width(), box.height(), 0xff000000, 0x80000000);
	}

	
	Object ksfg(Field f, Object o) {
		try {
			return f.get(o);
		}
		catch (IllegalArgumentException e) {
			throw new RuntimeException(e);
		}
		catch (IllegalAccessException e) {
			throw new RuntimeException(e);
		}
	}
}
