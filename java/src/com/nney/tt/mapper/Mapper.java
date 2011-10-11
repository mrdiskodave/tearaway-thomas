package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.AlienInfo;
import com.nney.tt.AlienInfoMap;
import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.tt.WorldServicesToMapper;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.HasKeys;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.tt.input.LocksKeyAdaptor;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.TeeKeyAdaptor;
import com.nney.tt.map.GameMap;
import com.nney.tt.sprites.AnimsPool;

/**
 * A level editor.
 * 
 * Keys:
 * 
 * <pre>
 * [A] Alien Tool - for changing aliens
 * 		LMB - select alien
 * 		LMB - change alien properties by dragging yellow control points
 * 		LMB - change alien properties by clicking on the panel at the bottom of the screen
 * 		Cursor Keys - nudge a control point by one pixel
 *      [C] - Copy alien to the mouse
 *      [pageup/down] - Choose alien
 *      [N] - New Alien
 * [D] Draw Tool - for changing blocks
 * 		Hold RMB - temporary use of the Block Chooser Tool from the Drawing Tool
 * 		Hold ALT - block choice follows mouse movements
 *                  (useful for drawing multi-block things from the block palette)
 *      Ctrl+CursorKeys change block
 * [B] Block Chooser Tool - full screen current-block choosing tool
 * 		LMB - select block
 * 		Cursor Keys - change block
 * [H] Hand Tool - for panning around
 * 		Hold SHIFT to go faster
 * 
 * Hold:SPACE - temporary use of the Hand Tool from other tools
 * [CTRL+Z] undo (endless - all changes)
 * [CTRL+Y] redo
 * 
 * A mini block chooser that uses CTRL with cursors or '0'.
 * And also CTRL+M to toggle showing block masks.
 * And also CTRL+V to toggle visibility of hidden blocks (magic floors etc).
 * Is available in the Draw
 * </pre>
 * 
 * Mini
 */
public class Mapper implements ButtonPressServices {
	private static final int COPY_LOCK = Locks.LOCK_SHIFT;

	private static final int PASTE_BUFFER_END = Keyboard.KEY_F12;

	private static final int PASTE_BUFFER_START = Keyboard.KEY_F1;

	final static public int MAPPER_KEY = Keyboard.KEY_TAB;

	private static final int COL_BACKGROUND = 0xff0080ff;

	private boolean masksVis;
	private boolean hiddenVis;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	final private int blockCount;
	private int paletteTimer;

	final MapperGC mgc;
	final private Pointer mouse;
	final WorldServicesToMapper srv;
	private final GameMap gameMap;

	private final SaveMapBlock[] slots = new SaveMapBlock[12];

	private EditConsolidator edit;

	private CollidableList<BatRecord> batRecords = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttonRecords;

	private AlienEdit alienEdit;

	private HoverStatus<ButtonRecord> hoverStatus = new HoverStatus<ButtonRecord>();
	private Alien selectedAlien;

	private MapperMousePosition mmp = new MapperMousePosition();

	private StatusLayer statusLayer;

	private UndoControler undoControler;

	private HasKeys keyboard;

	private Runnable pen;

	private Coord marker;

	private boolean alienMode;

	private AlienPalette alienPalette;

	//
	// stuff to do with the message
	//
	private int messTimer;

	private String messText;

	private final AnimsPool animsPool;

	// ---------------------------------------------------------------------------
	// MAPPER
	// ---------------------------------------------------------------------------

	public Mapper(AlienInfoMap alienInfoMap, AnimsPool animsPool, GameMap gameMap, WorldServicesToMapper srv,
			Pointer mouse, Keyboard keyboard, GraphicsContext gc, Font debugFont) {

		this.animsPool = animsPool;

		this.srv = srv;
		this.gameMap = gameMap;
		this.mouse = mouse;
		this.keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(mouse, keyboard));

		blockCount = srv.getBlocksHolder().getBlockCount();
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(gc, debugFont, colorCycler);

		ArrayList<AlienInfo> ais = new ArrayList<AlienInfo>();
		for (String name : alienInfoMap.queryNames()) {
			ais.add(alienInfoMap.getByName(name));
		}
		alienPalette = new AlienPalette(ais, mgc, animsPool);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		srv.load(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public void redo() {
				srv.reinstate(alien);
				setSelectedAlien(alien);
			}

			@Override
			public void undo() {
				deleteAlien(alien);
			}
		};
		undoControler.add(u);
	}

	public BlockPalette makeBP() {
		return new BlockPalette(mgc, srv.getBlocksHolder());
	}

	public void init() {
		undoControler = new UndoControler();
	}

	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	void drawBlockCursor() {
		Coord box = mmp.worldBlocks();
		box.mul(Const.BLOCK_SIZE);
		box.sub(srv.getScreenPosition());
		mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_CURRENT_BLOCK));
	}

	public void run() {
		mgc.nextFrame();
		mmp.update(mouse, getScreenPosition());

		statusLayer = new TopDownStatusLayer(mgc);

		boolean palettes = true;
		int k = keyboard.justPressed();

		if (pen != null) {
			pen.run();
			drawLevel();
		}
		else if (keyboard.isDown(Keyboard.KEY_SPACE)) {
			if (keyboard.isDown(Pointer.KEY_LEFT)) {
				scroll(mmp.pixelsDelta());
			}
			drawLevel();
		}
		else if (!alienMode && keyboard.isDown(Pointer.KEY_RIGHT)) {
			blockSelectionKeys(k);
			blockChoosingMode();
			palettes = false;
		}
		else if (k == MAPPER_KEY) {
			srv.quitMapper(mmp.worldPixels());
			drawLevel();
		}
		else {
			if (alienMode) {
				final BatRecord bat = batRecords.find(mmp.worldPixels());

				ButtonRecord button = findButton();
				hoverStatus.move(button);

				if (k == Pointer.KEY_LEFT) {
					if (button != null) {
						hoverStatus.down(button);
						startPen(new Pen() {
							@Override
							void stroke() {
								hoverStatus.move(findButton());
							};

							@Override
							public void up() {
								ButtonRecord b = findButton();
								if (hoverStatus.up(b)) {
									startAlienEdit();
									b.press();
									endAlienEdit();
								}
							}
						});
					}
					else if (bat == null) {
						startPen(new Pen() {
							@Override
							void stroke() {
								selectNearestAlien(mmp.worldPixels());
							}
						});
					}
					else {
						final Coord batGrip = mmp.worldPixels().sub2(bat.where());
						startAlienEdit();
						startPen(new Pen() {
							@Override
							public void stroke() {
								bat.onMove(mmp.worldPixels().sub2(batGrip));
							}

							@Override
							public void up() {
								endAlienEdit();
							}
						});
					}
				}
				else {
					Coord nudge = getNudge(k);
					if (nudge != null) {
						startAlienEdit();
						bat.onMove(nudge);
						endAlienEdit();
					}
				}

				if (haveAlien()) {
					if (k == Keyboard.KEY_DELETE) deleteSelectedAlien();
					if (k == Keyboard.KEY_C) copySelectedAlien();
				}
				if (k == Keyboard.KEY_N) createAlien();
				keyboardAlienChoice(k);

				if (k == Keyboard.KEY_D) {
					alienMode = false;
					marker = null;
					paletteTimer = 0;
					say("Drawing mode");
				}
			}
			else {
				if (k == Pointer.KEY_LEFT) {
					startBlockEdit();
					startPen(new Pen() {
						@Override
						public void stroke() {
							edit.setBlock(mmp.worldBlocks(), getCurrentBlock());
						}

						@Override
						public void up() {
							endBlockEdit();
						}
					});
				}
				if (k == Keyboard.KEY_I) {
					setCurrentBlock(gameMap.getBlock(mmp.worldBlocks()));
				}
				if (k == Keyboard.KEY_M) {
					marker = mmp.worldBlocks();
				}
				if (k == Keyboard.KEY_F) {
					fillRect();
				}
				if (k >= COPY_LOCK + PASTE_BUFFER_START && k <= COPY_LOCK + PASTE_BUFFER_END) {
					int slotNumber = k - (COPY_LOCK + PASTE_BUFFER_START);
					copyRect(slotNumber);
					marker = null;
					say("Copied into slot " + slotNumber);
				}
				if (k >= PASTE_BUFFER_START && k <= PASTE_BUFFER_END) {
					int slotNumber = k - PASTE_BUFFER_START;
					pasteRect(slotNumber);
					marker = null;
					say("Pasted from slot " + slotNumber);
				}
				if (keyboard.isDown(Keyboard.KEY_T)) {
					Coord c = mmp.worldBlocksDelta();
					changeCurrentBlock(c.x, c.y);
				}
				blockSelectionKeys(k);

				if (k == Keyboard.KEY_A) {
					alienMode = true;
					paletteTimer = 0;
					say("Alien mode");
				}
			}

			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Z) undoControler.undo();
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Y) undoControler.redo();
			if (k == Keyboard.KEY_ESCAPE) {
				paletteTimer = 0;
				messTimer = 0;
			}
			if (k == Locks.LOCK_MENU + Keyboard.KEY_S) {
				
				say("Saved");
			}

			drawLevel();
			if (!alienMode) {
				drawBlockCursor();
			}
		}

		if (palettes) {
			if (alienMode) showSelectedAlienProps();
			drawPalettes();
		}

		if (messTimer != 0) {
			messTimer--;
			statusLayer.draw(statusLayer.width() - messText.length(), 0, ButtonState.PASSIVE, messText);
		}
	}

	private ButtonRecord findButton() {
		if (buttonRecords == null) return null;
		return buttonRecords.find(mmp.screenPixels());
	}

	private void startPen(final Pen p) {
		p.stroke();
		pen = new Runnable() {
			@Override
			public void run() {
				if (keyboard.isDown(Pointer.KEY_LEFT)) {
					p.stroke();
				}
				else {
					p.up();
					pen = null;
				}
			}
		};
	}

	private void drawPalettes() {
		if (paletteTimer != 0) {
			paletteTimer--;
			if (alienMode) {
				alienPalette.showAlienPalette();
			}
			else {
				makeBP().showSmallPalette(getCurrentBlock());
			}
		}
	}

	private void drawLevel() {
		mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
		srv.drawForMapper();

		drawRect();
	}

	private void drawRect() {
		Box box = getRect();
		if (box != null) {
			box.mult(Const.BLOCK_SIZE);
			box.shrink(1);
			box.sub(srv.getScreenPosition());
			mgc.drawBox(box.left, box.top, box.width(), box.height(), mgc.process(0xff00ffff));
		}
	}

	private Box getRect() {
		if (marker == null) return null;
		return Box.fromTwoCorners(mmp.worldBlocks(), marker);
	}

	private void say(String s) {
		messTimer = 100;
		messText = s;
	}

	private void keyboardAlienChoice(int k) {

		AlienInfo current = alienPalette.get();
		if (k == Keyboard.KEY_NEXT) alienPalette.next();
		if (k == Keyboard.KEY_PRIOR) alienPalette.prev();
		if (k == Keyboard.KEY_I && haveAlien()) alienPalette.find(getSelectedAlien().alienInfo);
		if (alienPalette.get() != current) {
			paletteTimer = 100;
		}
	}
	
	private Alien makeAlien(AlienInfo ai) {
		Alien a = ai.instantiateAttach();
		a.connect(animsPool);
		return a;
	}

	private void createAlien() {
		AlienInfo ai = alienPalette.get();
		Alien a = makeAlien(ai);
		a.resetTo(mmp.worldPixels());
		APS.validateAlien(a);
		createAlienWithUndoRedo(a);
	}

	void blockSelectionKeys(int k) {
		if (k == Keyboard.KEY_UP) changeCurrentBlock(0, -1);
		if (k == Keyboard.KEY_DOWN) changeCurrentBlock(0, 1);
		if (k == Keyboard.KEY_LEFT) changeCurrentBlock(-1, 0);
		if (k == Keyboard.KEY_RIGHT) changeCurrentBlock(1, 0);
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_M) {
			masksVis = !masksVis;
			srv.setBlockConfig(masksVis, hiddenVis);
		}
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_V) {
			hiddenVis = !hiddenVis;
			srv.setBlockConfig(masksVis, hiddenVis);
		}
	}

	void blockChoosingMode() {
		int hoverBlock = makeBP().showBigPalette(getCurrentBlock(), mmp.screenPixels());
		if (keyboard.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			setCurrentBlock(hoverBlock);
		}
	}

	private void changeCurrentBlock(int dx, int dy) {
		int delta = BlockPalette.getPaletteDelta(dx, dy);
		int b = delta + getCurrentBlock();
		if (b < 0) {
			b += blockCount;
		}
		if (b >= blockCount) {
			b -= blockCount;
		}
		setCurrentBlock(b);
	}

	private void startBlockEdit() {
		System.out.println("Start edit");
		assert edit == null;
		edit = new EditConsolidator(gameMap);
	}

	private void endBlockEdit() {
		System.out.println("Submit edit");
		assert edit != null;
		MapSymmetricalUndoRedo u = edit.endEdit();
		if (u != null) submitEdit(u);
		edit = null;
	}

	private void scroll(Coord delta) {
		if (keyboard.isDown(Keyboard.KEY_SHIFT)) {
			delta.mul(4);
		}
		srv.setScreenPosition(srv.getScreenPosition().sub2(delta));
	}

	// --------------------------------------------------

	private void selectNearestAlien(Coord c) {
		setSelectedAlien(srv.findNearestAlien(c));
	}

	private boolean haveAlien() {
		return getSelectedAlien() != null;
	}

	private Alien getSelectedAlien() {
		if (selectedAlien != null && selectedAlien.remove) {
			selectedAlien = null;
		}
		return selectedAlien;
	}

	private void setSelectedAlien(Alien s) {
		selectedAlien = s;
		buttonRecords = null;

	}

	private void showSelectedAlienProps() {
		if (haveAlien()) {
			//
			// bats
			//

			BatGCImpl batGc = new BatGCImpl(getScreenPosition(), mgc);
			batGc.drawSuperBat(getSelectedAlien().getLocation());

			List<Prop> props = APS.propsForAlien(getSelectedAlien());

			// bats
			batRecords.clear();
			for (Prop p : props) {
				p.drawAuxBatStuff(batGc);

				ArrayList<Bat> lbats = new ArrayList<Bat>();
				p.getBats(lbats);
				for (Bat lbat : lbats) {
					batRecords.add(new CommonBatRecord(lbat));
					batGc.drawBat(lbat.where());
				}

			}

			// a super-bat that moves all the alien's visual
			// properties in one go
			final Alien alien = getSelectedAlien();
			BatRecord superBat = new BatRecord() {
				@Override
				public boolean inside(Coord c) {
					return BatGCImpl.boxForSuperBat(where()).inside(c);
				}

				@Override
				public void onMove(Coord c) {
					APS.movePropsAbsolute(alien, c);
				}

				@Override
				public Coord where() {
					return alien.getLocation();
				}
			};
			batRecords.add(superBat);

			//
			// property descriptions and buttons
			//

			// are we reading buttonRecords?
			int cursor = 0;
			if (buttonRecords == null) {
				// no we're building them!
				buttonRecords = new CollidableList<ButtonRecord>();
				cursor = -1;
			}
			// TODO: ^^^ugly! ideally then generation and drawing
			// phases would be entirely separate

			int y = 0;
			statusLayer.touch(y++);
			statusLayer.touch(y++);
			String docs = "";
			for (Prop p : props) {
				if (statusLayer.getBox(0, y, -1, 1).inside(mmp.screenPixels())) {
					docs = p.doc();
				}
				statusLayer.draw(0, y, ButtonState.PASSIVE, clip(p.name(), 10));
				statusLayer.draw(15, y, ButtonState.PASSIVE, clip(p.text(), 20));
				int x = 35;

				ArrayList<Button> buttons = new ArrayList<Button>();
				p.getButtons(buttons, this);
				for (Button button : buttons) {
					String buttonText = "[" + button.name() + "]";
					ButtonRecord buttonRecord;
					if (cursor < 0) {
						Box buttonBox = statusLayer.getBox(x, y, buttonText);
						buttonRecord = new ButtonRecord(button, buttonBox);
						buttonRecords.add(buttonRecord);
					}
					else {
						buttonRecord = buttonRecords.get(cursor++);
					}
					statusLayer.draw(x, y, hoverStatus.status(buttonRecord), buttonText);
					x += buttonText.length() + 1;
				}
				y++;
			}
			statusLayer.draw(0, 0, ButtonState.PASSIVE, docs);
		}
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

	private void deleteAlien(Alien a) {
		a.done();
		setSelectedAlien(null);
	}

	public Coord getNudge(int k) {
		switch (k) {
		case Keyboard.KEY_UP:
			return new Coord(0, -1);
		case Keyboard.KEY_DOWN:
			return new Coord(0, 1);
		case Keyboard.KEY_LEFT:
			return new Coord(-1, 0);
		case Keyboard.KEY_RIGHT:
			return new Coord(1, 0);
		}
		return null;
	}

	private void startAlienEdit() {
		assert alienEdit == null;
		Alien a = getSelectedAlien();
		alienEdit = new AlienEdit(a);
	}

	private void endAlienEdit() {
		if (alienEdit.containsAnything()) {
			undoControler.add(alienEdit);
		}
		alienEdit = null;
	}

	@Override
	public Coord screenCentre() {
		return getScreenPosition().add2(mgc.centreDisplacement());
	}

	@Override
	public void setScreenCentre(Coord c) {
		srv.setScreenPosition(c.sub2(mgc.centreDisplacement()));
	}

	public void deleteSelectedAlien() {
		final Alien a = getSelectedAlien();
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public void undo() {
				srv.reinstate(a);
				setSelectedAlien(a);
			}

			@Override
			public void redo() {
				deleteAlien(a);
			}
		});
	}

	public void copySelectedAlien() {
		final Alien src = getSelectedAlien();
		if (!src.alienInfo.internal()) {
			final Alien dest = makeAlien(src.alienInfo);
			APS.copyProps(src, dest);
			APS.movePropsAbsolute(dest, mmp.worldPixels());
			createAlienWithUndoRedo(dest);
		}
	}

	private void submitEdit(MapSymmetricalUndoRedo u) {
		if (!u.changesNothing()) undoControler.redoThenAdd(u);
	}

	private void pasteRect(int slotNumber) {
		SaveMapBlock slot = slots[slotNumber];
		if (slot != null) {
			Coord c = mmp.worldBlocks();
			// does it fit?
			boolean itFits = c.x + slot.w <= GameMap.MAP_WIDTH && c.y + slot.h <= GameMap.MAP_HEIGHT;
			if (itFits) {
				// paste it!
				MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, c.x, c.y, slot);
				submitEdit(u);
			}
		}
	}

	private void copyRect(int slotNumber) {
		Box rectangle = getRect();
		if (rectangle == null) return;
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.read(rectangle.left, rectangle.top, gameMap);
		slots[slotNumber] = s;
		System.out.println("SLOT " + slotNumber);
		// slots[slotNumber].dump();
	}

	private void fillRect() {
		Box rectangle = getRect();
		if (rectangle == null) return;
		SaveMapBlock s = new SaveMapBlock(rectangle.width(), rectangle.height());
		s.fill(getCurrentBlock());
		MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, rectangle.left, rectangle.top, s);
		submitEdit(u);
	}

	private int getCurrentBlock() {
		return currentBlock;
	}

	private void setCurrentBlock(int currentBlock) {
		this.currentBlock = currentBlock;
		paletteTimer = 100;
	}

	//
	// Delegates:
	//

	public Coord getScreenPosition() {
		return srv.getScreenPosition();
	}

	@Override
	public boolean playerFall(Coord where, int fallMax) {
		return srv.playerFall(where, fallMax);
	}
}
