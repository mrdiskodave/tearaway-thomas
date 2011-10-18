package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.AlienFactory;
import com.nney.tt.AlienInfo;
import com.nney.tt.AlienInfoMap;
import com.nney.tt.AlienServices;
import com.nney.tt.AlienTracker;
import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.tt.FrameDrawer;
import com.nney.tt.OuterWorld;
import com.nney.tt.PersistedLevel;
import com.nney.tt.ScreenPosition;
import com.nney.tt.World;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.HasKeys;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.tt.input.LocksKeyAdaptor;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.TeeKeyAdaptor;
import com.nney.tt.map.GameMap;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.Math2;

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
public class Mapper implements ButtonPressServices, FrameDrawer {
	private final static int COPY_LOCK = Locks.LOCK_SHIFT;

	private final static int PASTE_BUFFER_END = Keyboard.KEY_F12;

	private final static int PASTE_BUFFER_START = Keyboard.KEY_F1;

	private final static int MAPPER_KEY = Keyboard.KEY_TAB;

	private final static int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	private int paletteTimer;

	private final MapperGC mgc;
	private final Pointer mouse;
	private final GameMap gameMap;

	private final SaveMapBlock[] slots = new SaveMapBlock[12];

	private EditConsolidator edit;

	private final CollidableList<BatRecord> batRecords = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttonRecords;

	private AlienEdit alienEdit;

	private final HoverStatus<ButtonRecord> hoverStatus = new HoverStatus<ButtonRecord>();
	private Alien selectedAlien;

	private final MapperMousePosition mmp = new MapperMousePosition();

	private StatusLayer topDownStatusLayer;

	private final UndoControler undoControler = new UndoControler();

	private final HasKeys keyboard;

	private Runnable pen;

	private Coord marker;

	private boolean alienMode;

	private final AlienPalette alienPalette;

	//
	// stuff to do with the message
	//
	private int messTimer;

	private String messText;

	private final OuterWorld ow;

	private final AnimsPool animsPool;

	private final ScreenPosition scr;

	private final AlienInfoMap alienInfoMap = new AlienInfoMap();

	private boolean seeHidden = true;

	private boolean seeMasks;

	private final AlienTracker alienTracker = new AlienTracker();

	private String worldName;

	private final AlienServices alienServices = new MapperAlienServices(this);

	private BottomUpStatusLayer bottomUpStatusLayer;

	void directDrawSprite(Coord c, final Sprite s, boolean drawWhite) {
		Coord screen = scr.position();
		final int x = c.x - screen.x;
		final int y = c.y - screen.y;
		s.drawByHandle(x, y, drawWhite);
	}

	void drawDebugText(Coord c, String text) {
		Coord a = c.sub2(scr.position());
		mgc.drawText(a.x, a.y, 0xff00ff00, 0xff000000, text);
	}

	public Mapper(OuterWorld ow) {
		this.ow = ow;
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(ow.gc, ow.fonts.debugFont, colorCycler);
		scr = new ScreenPosition(mgc.screenWidth(), mgc.screenHeight());
		scr.setMapBoundsInPixels(World.WHOLE_MAP_BOUNDS_IN_PIXELS);
		keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(ow.mouse, ow.keyboard));
		mouse = ow.mouse;
		animsPool = ow.animsPool;

		AlienFactory af = new AlienFactory(alienInfoMap);
		PersistedLevel pl = new PersistedLevel();
		pl.populateFromLevelInfo(af, ow.levelNumber);
		worldName = alienInfoMap.getWorldName();

		for (String a : alienInfoMap.queryAnimList()) {
			animsPool.load(a);
		}

		gameMap = pl.gameMap;
		gameMap.applyCompress(loadBlockSet().wi.blockRandomisationTable);

		List<Alien> aliens = pl.getAliens();
		for (Alien alien : aliens) {
			if (alien instanceof PlayerAlien) {
				PlayerAlien playerPos = (PlayerAlien) alien;
				System.out.println("SNAP TO " + playerPos.c);
				scr.snapTo(playerPos.c);
			}
			alien.connect(animsPool);
			load(alien);
		}

		ArrayList<AlienInfo> ais = new ArrayList<AlienInfo>();
		for (String name : alienInfoMap.queryNames()) {
			ais.add(alienInfoMap.getByName(name));
		}
		alienPalette = new AlienPalette(ais, mgc, animsPool);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		load(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public void redo() {
				reinstate(alien);
				setSelectedAlien(alien);
			}

			@Override
			public void undo() {
				deleteAlien(alien);
			}
		};
		undoControler.add(u);
	}

	public void load(Alien alien) {
		alien.load(alienServices);
		alienTracker.delayedAdd(alien);
	}

	public BlockPalette makeBP() {
		return new BlockPalette(mgc, loadBlockSet());
	}

	/**
	 * The colour we use to highlight the current block.
	 */
	private static final int COL_CURRENT_BLOCK = 0xffff0000;

	void drawBlockCursor() {
		Coord box = mmp.worldBlocks();
		box.mul(Const.BLOCK_SIZE);
		box.sub(getScreenPosition());
		mgc.drawBox(box.x, box.y, Const.BLOCK_SIZE, Const.BLOCK_SIZE, mgc.process(COL_CURRENT_BLOCK));
	}

	@Override
	public void drawFrame() {
		
//		at();
//		System.exit(1);
		
		mgc.nextFrame();
		mmp.update(new Coord(mouse.getX(), mouse.getY()), getScreenPosition());

		topDownStatusLayer = new TopDownStatusLayer(mgc);
		bottomUpStatusLayer = new BottomUpStatusLayer(mgc);

		boolean palettes = true;
		int k = keyboard.justPressed();
		// System.out.println(String.format("PRESSED:%08x", k));

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
			quitMapper(mmp.worldPixels());
			drawLevel();
		}
		else {
			if (alienMode) {
				alienMode(k);
			}
			else {
				blockMode(k);
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
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_G) {
				say("Position:" + mmp.worldPixels() + "pixels " + mmp.worldBlocks() + "blocks");
			}

			drawLevel();
		}

		if (palettes) {
			if (alienMode) showSelectedAlienProps();
			drawPalettes();

			if (messTimer != 0) {
				messTimer--;
				// topDownStatusLayer.draw(topDownStatusLayer.width() -
				// messText.length(), 0, ButtonState.PASSIVE, messText);
				bottomUpStatusLayer.draw(0, 0, ButtonState.PASSIVE, messText);
			}
		}
	}

	private void blockMode(int k) {
		if (k == Pointer.KEY_LEFT) {
			startBlockEdit();
			startPen(k, new Pen() {
				@Override
				public void stroke() {
					edit.setBlock(mmp.worldBlocks(), getCompressedCurrentBlock(), false);
					drawBlockCursor();
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
			marker = marker==null ? mmp.worldBlocks() : null;
		}
		if (k == Keyboard.KEY_F) {
			if (marker!=null) {
				fillRect();
			}
			else {
				final int blk = gameMap.getBlock(mmp.worldBlocks());
				BlockTest test = new BlockTest() {
					@Override
					public boolean test(int b) {
						return b==blk;
					}};
				floodFill(test);
			}
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
		if (k == Keyboard.KEY_H) {
			generateToyland();
		}
	}

	private void alienMode(int k) {
		int kns = k & (~Locks.LOCK_SHIFT);
		final BatRecord bat = batRecords.find(mmp.worldPixels());

		ButtonRecord button = findButton();
		hoverStatus.move(button);

		if (k == Pointer.KEY_RIGHT) {
			startPen(k, new Pen() {
				@Override
				void stroke() {
					selectNearestAlien(mmp.worldPixels());
				}
			});
		}
		if (kns == Pointer.KEY_LEFT) {
			if (button != null && k == kns) {
				hoverStatus.down(button);
				startPen(k, new Pen() {
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
			else if (bat != null) {
				final Coord batGrip = mmp.worldPixels().sub2(bat.where());
				startAlienEdit();
				startPen(kns, new Pen() {
					Coord origin;

					public Coord where() {
						return mmp.worldPixels().sub2(batGrip);
					}

					private Coord whereSnapped() {
						boolean isDown = keyboard.isDown(Locks.LOCK_SHIFT);
						if (isDown) {
							if (origin == null) origin = where();
						}
						else {
							origin = null;
						}
						return computeSnap(where(), origin, 8);
					}

					@Override
					public void stroke() {
						bat.onMove(whereSnapped());
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

	/**
	 * Compute a new position that is the given position moved to lie on a spoke
	 * radiating from the given origin.
	 * 
	 * @param pos
	 *            The original position.
	 * @param origin
	 *            The position of the origin.
	 * @param spokes
	 *            The number of spokes radiating from the origin. The first
	 *            spoke points right and they are equally spaced. e.g. 4 would
	 *            mean "snap to the X and Y axis" while 8 would mean
	 *            "snap to the axis or the diagonals". Zero has a special
	 *            meaning of
	 *            "don't do anything just return the input pos unmodified".
	 * @return The computed new position.
	 */
	private Coord computeSnap(Coord pos, Coord origin, int spokes) {
		if (origin == null) return pos;
		double spokeSize = (2 * Math.PI) / spokes;
		Coord d = pos.sub2(origin);
		double length = Math.sqrt(d.squareOfLength());
		double angle = Math.atan2(d.y, d.x);
		angle /= spokeSize;
		angle = Math.round(angle);
		angle *= spokeSize;
		long y = Math.round(Math.sin(angle) * length);
		long x = Math.round(Math.cos(angle) * length);
		Coord e = new Coord((int) x, (int) y);
		return origin.add2(e);
	}

	private ButtonRecord findButton() {
		if (buttonRecords == null) return null;
		return buttonRecords.find(mmp.screenPixels());
	}

	private void startPen(final int k, final Pen p) {
		pen = new Runnable() {
			@Override
			public void run() {
				if (keyboard.isDown(k)) {
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
		scr.drawGrid(mgc);
		scr.drawTheMap(gameMap, loadBlockSet());
		drawRect();
		updateAliens();
		if (!alienMode) {
			drawBlockCursor();
		}
	}

	private void drawRect() {
		Box box = getRect();
		if (box != null) {
			box.mult(Const.BLOCK_SIZE);
			box.shrink(1);
			box.sub(getScreenPosition());
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
		return ai.instantiateAttach();
	}

	private void createAlien() {
		AlienInfo ai = alienPalette.get();
		Alien a = makeAlien(ai);
		a.connect(animsPool);
		a.resetTo(mmp.worldPixels());
		APS.validateAlien(a);
		createAlienWithUndoRedo(a);
	}

	void blockSelectionKeys(int k) {
		if (k == Keyboard.KEY_UP) changeCurrentBlock(0, -1);
		if (k == Keyboard.KEY_DOWN) changeCurrentBlock(0, 1);
		if (k == Keyboard.KEY_LEFT) changeCurrentBlock(-1, 0);
		if (k == Keyboard.KEY_RIGHT) changeCurrentBlock(1, 0);
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_M) seeMasks = !seeMasks;
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_H) seeHidden = !seeHidden;
	}

	private void blockChoosingMode() {
		int hoverBlock = makeBP().showBigPalette(getCurrentBlock(), mmp.screenPixels());
		if (keyboard.isDown(Pointer.KEY_LEFT) && hoverBlock >= 0) {
			setCurrentBlock(hoverBlock);
		}
	}

	private void changeCurrentBlock(int dx, int dy) {
		int delta = BlockPalette.getPaletteDelta(dx, dy);
		int blockCount = loadBlockSet().getBlockCount();
		int b = delta + getCurrentBlock() + blockCount;
		b %= blockCount;
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
		setScreenPosition(getScreenPosition().sub2(delta));
	}

	// --------------------------------------------------

	private void selectNearestAlien(Coord c) {
		setSelectedAlien(findNearestAlien(c));
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
			topDownStatusLayer.touch(y++);
			topDownStatusLayer.touch(y++);
			String docs = "";
			for (Prop p : props) {
				if (topDownStatusLayer.getBox(0, y, -1, 1).inside(mmp.screenPixels())) {
					docs = p.doc();
				}
				topDownStatusLayer.draw(0, y, ButtonState.PASSIVE, clip(p.name(), 10));
				topDownStatusLayer.draw(15, y, ButtonState.PASSIVE, clip(p.text(), 20));
				int x = 35;

				ArrayList<Button> buttons = new ArrayList<Button>();
				p.getButtons(buttons, this);
				for (Button button : buttons) {
					String buttonText = "[" + button.name() + "]";
					ButtonRecord buttonRecord;
					if (cursor < 0) {
						Box buttonBox = topDownStatusLayer.getBox(x, y, buttonText);
						buttonRecord = new ButtonRecord(button, buttonBox);
						buttonRecords.add(buttonRecord);
					}
					else {
						buttonRecord = buttonRecords.get(cursor++);
					}
					topDownStatusLayer.draw(x, y, hoverStatus.status(buttonRecord), buttonText);
					x += buttonText.length() + 1;
				}
				y++;
			}
			topDownStatusLayer.draw(0, 0, ButtonState.PASSIVE, docs);
		}
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

	private void deleteAlien(Alien a) {
		a.done();
		setSelectedAlien(null);
	}

	private Coord getNudge(int k) {
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
		setScreenPosition(c.sub2(mgc.centreDisplacement()));
	}

	private void deleteSelectedAlien() {
		final Alien a = getSelectedAlien();
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public void undo() {
				reinstate(a);
				setSelectedAlien(a);
			}

			@Override
			public void redo() {
				deleteAlien(a);
			}
		});
	}

	private void copySelectedAlien() {
		final Alien src = getSelectedAlien();
		if (!src.alienInfo.internal()) {
			createAlienWithUndoRedo(copyAlien(src));
		}
	}

	private Alien copyAlien(final Alien src) {
		final Alien dest = makeAlien(src.alienInfo);
		dest.connect(src);
		APS.copyProps(src, dest);
		APS.movePropsAbsolute(dest, mmp.worldPixels());
		return dest;
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
		s.fill(getCompressedCurrentBlock());
		MapSymmetricalUndoRedo u = new MapSymmetricalUndoRedo(gameMap, rectangle.left, rectangle.top, s);
		submitEdit(u);
	}

	private int getCurrentBlock() {
		return currentBlock;
	}

	private int getCompressedCurrentBlock() {
		return loadBlockSet().wi.blockRandomisationTable.compress(currentBlock);
	}

	private void setCurrentBlock(int currentBlock) {
		this.currentBlock = currentBlock;
		paletteTimer = 100;
		say("block=" + currentBlock);
	}

	// ---------------------------------------------------------------------------

	private void quitMapper(Coord mousePos) {

	}

	// gameMap.applyCompress(blockSet.wi.blockRandomisationTable);

	public Coord getScreenPosition() {
		return scr.position();
	}

	public void setScreenPosition(Coord c) {
		scr.setPosition(c);
	}

	private void updateAliens() {
		Box screenBox = scr.box();
		alienTracker.begin(screenBox);
		updateList(alienTracker.get(Alien.DEPTH_BG_SCENARY), screenBox);
		updateList(alienTracker.get(Alien.DEPTH_LIFTS_AND_COLLECTABLES), screenBox);
		updateList(alienTracker.get(Alien.DEPTH_ALIENS), screenBox);
		updateList(alienTracker.get(Alien.DEPTH_FG_SCENARY), screenBox);
	}

	private void updateList(List<Alien> alienList, Box screenBox) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			alien.freezeBounds = null;
			alien.mapperUpdate();
			if (alien.remove || alienTracker.perhapsFreeze(alien, screenBox)) {
				alienIterator.remove();
			}
		}
	}

	public Anim mapperLoadAnim(String animsName) {
		Anims anims = animsPool.expect(animsName);
		Anim anim = anims.find(0);
		return anim;
	}

	public Alien findNearestAlien(Coord c) {
		NearestAlienFinder n = new NearestAlienFinder(c);
		alienTracker.visitAll(n);
		return n.getAnswer();
	}

	public BlockSet loadBlockSet() {
		return ow.loadBlockSet(new BlockSet.Config(worldName, seeMasks, seeHidden));
	}

	public void reinstate(Alien alien) {
		alien.reinstate();
		alienTracker.delayedAdd(alien);
	}

	public boolean inTheGround(Coord c) {
		int block = gameMap.getBlock(c.div2(Const.BLOCK_SIZE));
		return loadBlockSet().maskHolder.inTheGround(block, c.x & Const.BLOCK_MASK, c.y & Const.BLOCK_MASK);
	}

	@Override
	public void fall(Coord c) {
		for (int x = 0; x < 64; x++) {
			c.y++;
			if (inTheGround(c)) {
				c.y--;
				return;
			}
		}
	}

	// TODO: that wiggly bug with block shuffling - cause is stop blocks! (draw
	// them)
	// TODO: test launch from here / test launch

	boolean isWall(int b) {
		return b >= 1 && b <= 4;
	}

	private boolean testWall(Coord coord, int i, int j) {
		int b = gameMap.safeGetBlock(coord.add2(new Coord(i, j)));
		return isWall(b);
	}
	
	interface BlockTest {
		boolean test(int b);
	}
	
	private void floodFill(BlockTest fillable) {
		startBlockEdit();
		
		// naive implementation but at least it is breadth first
		// so doesn't keep too many false leads
		ArrayList<Coord> positions = new ArrayList<Coord>();
		ArrayList<Coord> nextPositions = new ArrayList<Coord>();
		positions.add(mmp.worldBlocks());
		
		while (!positions.isEmpty()) {
			for (Coord s: positions) {
				if (!edit.isChangeAt(s) && fillable.test(gameMap.safeGetBlock(s))) {
					edit.setBlock(s, getCurrentBlock(), true);
					nextPositions.add(s.copyAndAdd(1, 0));
					nextPositions.add(s.copyAndAdd(-1, 0));
					nextPositions.add(s.copyAndAdd(0, 1));
					nextPositions.add(s.copyAndAdd(0, -1));
				}
			}
			ArrayList<Coord> t = nextPositions;
			nextPositions = positions;
			positions = t;
			nextPositions.clear();
		}
		
		say(edit.size()+ " blocks filled");
		endBlockEdit();
	}

	private void generateToyland() {
		int pc = 0;
		int pw = 0;
		System.out.println("Generating Intricacies Of Toyland");
		for (int y = 0; y < GameMap.MAP_HEIGHT; y++) {
			for (int x = 0; x < GameMap.MAP_WIDTH; x++) {
				Coord coord = new Coord(x, y);
				int b = gameMap.safeGetBlock(coord);

				boolean checkers = Math2.maskTest(x^y, 1);

				boolean wallEast = testWall(coord, 1, 0);
				boolean wallWest = testWall(coord, -1, 0);
				boolean wallNorthWest = testWall(coord, -1, -1);
				boolean wallNorth = testWall(coord, 0, -1);
				boolean wallSouth = testWall(coord, 0, 1);

				int walls[] = { 4, 3, 1, 2 };
				int spaces[] = { 0, 5, 3, 2, 4, -1, 6, 1 };
				
				int n = -1;
				if (isWall(b)) {
					int v = 0;
					if (wallWest) v |= 1;
					if (wallEast) v |= 2;
					n = walls[v];
				}
				else if (b >= 80 && b < 240) {
					if ((b % 20) < 14) {
						int v = 0;
						if (wallNorth) v|= 1;
						if (wallNorthWest) v|= 2;
						if (wallWest) v|= 4;
						n = spaces[v];

						
						// four blocks of style 
						// 1) 80 eyes - exit 48
						// 2) 87 diagonals - exit 52
						// 3) 160 grid - exit 51x4
						// 4) 167 waves - exit 54
						// magical blocks start at 46,
						// two for each, in order

						// 11 1
						// 12 3
						// 13 2
						// 14 4
						// 15 1!
						// 16 3
						// 17 2
						// 18 4
						// 19 3
						
						// does the width have to be 20?
						
						if (n>=0) {
//							n += 167;
							n += 160;
//							n += 80;
//							n += 87;
							if (!checkers) {
								n += 40;
							}
							if (wallSouth) {
								n += 20;
							}
						}
						else {
							System.out.println("Bad wall placement: "+b+" at "+coord);
						}
					}
					if (n<0) System.out.println("Mystery space: "+b+" at "+coord);
				}
				else if (b==0) {
					
				}
				else {
					System.out.println("Something else: "+b+" at "+coord);
				}
				
				

				if (n >= 0) {
					if (n != b) {
						System.out.println("Predicted " + n + " but saw " + b + " at " + coord);
						pw++;
					}
					else {
						pc++;
					}
				}
			}
		}
		System.out.println("Done! Correct:" + pc + " wrong:"+pw);
	}

}

// 167,207 as a checker board X
// 173,213 wall W&NW X
// 171,221 wall W X
// 170,210 wall NW X
// 168,208 wall W&NW&N X
// 172, wall N
// 169, wall N&NW
