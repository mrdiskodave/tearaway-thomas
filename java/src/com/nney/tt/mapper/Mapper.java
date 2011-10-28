package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.AlienFactory;
import com.nney.tt.AlienInfo;
import com.nney.tt.AlienInfoMap;
import com.nney.tt.AlienServices;
import com.nney.tt.BlockSet;
import com.nney.tt.Const;
import com.nney.tt.FrameDrawer;
import com.nney.tt.LevelInfo;
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
import com.nney.tt.props.Bat;
import com.nney.tt.props.Button;
import com.nney.tt.props.ButtonPressServices;
import com.nney.tt.props.OPS;
import com.nney.tt.props.Prop;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.CountingMap;
import com.nney.utils.ListUtil;
import com.nney.utils.Math2;

/**
 * A level editor.
 * 
 * <pre>
 * [A] Alien Mode:
 *   [RMB] near an alien to select alien - buttons and control points appear! 
 *   [LMB] on a control point to grab and drag it
 *         press [SHIFT] to constrain dragging to axises
 *   [CURSOR KEYS] on a control point to nudge it
 *   [LMB] on a button to press it (e.g. to toggle an aliens boolean property)
 *   [C] copy the selected alien
 *   [PAGEUP/PAGEDOWN] change current alien type
 *   [I] eye dropper - sets the current alien type from the selected alien 
 *   [N] new alien (of the current alien type)
 *   [DELETE] delete the selected alien
 *   [F] find the selected alien (i.e. scroll to it)
 * 
 * [D] Drawing Mode:
 *   [LMB] draw with the current block
 *   [I] eye dropper - sets the current block from the map
 *   [CURSOR KEYS] change the current block
 *   hold [C] to make the current block chase mouse movement (try it)
 *   [M] start marking a rectangle of blocks during which:
 *     [M] cancel marking
 *     [F1-12] copy the rectangle of blocks into a numbered slot
 *     [F] fill the rectangle with the current block
 *     [DELETE] delete those blocks (i.e. fill rectangle with block 0) 
 *   [F1-12] paste blocks from numbered slot
 *   [F] flood fill with the current block
 *   
 *   In Drawing Mode (even though it is an alien function) [F1-F12] and [DELETE]
 *   work on aliens when you hold down Ctrl (i.e. every slot can hold blocks,
 *   aliens or both).
 *   
 *   [Ctrl+A] start marking a rectangle of blocks covering the whole map
 *   [Ctrl+M] toggle seeing block masks
 *   [Ctrl+I] toggle seeing hidden blocks
 * 
 *   hold [RMB] for full screen block chooser:
 *     [LMB] to pick.
 *     [CURSOR KEYS], [0], [CTRL+M] and [CTRL+I] work in here too
 * 
 * Always:
 * hold [SPACE] to pan around with the [LMB] (hold [SHIFT] to go faster)
 * [NUMPAD5] jump to the middle of the level
 *           (and the eight numbered keys around it work as expected)
 * [Ctrl+G] where am I?
 * [Ctrl+Z] endless undo
 * [Ctrl+Y] endless redo
 * [ESCAPE] reset
 *          (removes temporary floating palettes and other statefulness)
 * [Alt+T] small test (test the level from the mouse position without the intro)
 * [Alt+Shift+T] big test (test the whole level as the player would experience it)
 * [Alt+S] save the level
 * </pre>
 */
public class Mapper implements ButtonPressServices, FrameDrawer {
	private static final int ALIENS_LOCK = Locks.LOCK_CONTROL;

	interface AlienPredicate {
		boolean is(Alien t);
	}

	private final CountingMap<AlienInfo> survey = new CountingMap<AlienInfo>();

	private static final int SLOT_COUNT = 12;

	private final static int PASTE_BUFFER_START = Keyboard.KEY_F1;
	private final static int PASTE_BUFFER_END = PASTE_BUFFER_START + SLOT_COUNT - 1;

	private final static int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	private int paletteTimer;

	private final MapperGC mgc;
	private final Pointer mouse;
	private final GameMap gameMap;

	class SavedAlienSlot {
		public final Coord corner;
		public final List<Alien> aliens;

		SavedAlienSlot(Coord corner, List<Alien> aliens) {
			this.corner = corner;
			this.aliens = aliens;
		}
	}

	private final SavedMapBlock[] blockSlots = new SavedMapBlock[SLOT_COUNT];

	private final SavedAlienSlot[] alienSlots = new SavedAlienSlot[SLOT_COUNT];

	private EditConsolidator edit;

	private final CollidableList<BatRecord> batRecords = new CollidableList<BatRecord>();
	private CollidableList<ButtonRecord> buttonRecords;

	private ObjectEdit alienEdit;

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

	private final AlienInfoMap alienInfoMap;

	private boolean seeHidden = true;

	private boolean seeMasks;

	private MapperAlienTracker alienTracker = new MapperAlienTracker();

	private String worldName;

	private final AlienServices alienServices = new MapperAlienServices(this);

	private BottomUpStatusLayer bottomUpStatusLayer;

	private LevelInfo levelInfo;

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

		scr = new ScreenPosition(mgc.screenWidth(), mgc.screenHeight(), new Coord(50, 50));

		Box scrollBounds = World.WHOLE_MAP_BOUNDS_IN_PIXELS.copy();
		scrollBounds.left -= mgc.screenWidth() - 1;
		scrollBounds.top -= mgc.screenHeight() - 1;
		scrollBounds.right += mgc.screenWidth() - 1;
		scrollBounds.bottom += mgc.screenHeight() - 1;
		scr.setMapBoundsInPixels(scrollBounds, World.WHOLE_MAP_BOUNDS_IN_PIXELS);

		keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(ow.mouse, ow.keyboard));
		mouse = ow.mouse;
		animsPool = ow.animsPool;

		PersistedLevel pl = new PersistedLevel(ow.levelNumber, null);
		levelInfo = pl.getLevelInfo();
		alienInfoMap = new AlienInfoMap(levelInfo.worldName);

		worldName = alienInfoMap.getName();

		for (String a : alienInfoMap.queryAnimList()) {
			animsPool.load(a);
		}

		gameMap = pl.getMap();
		gameMap.applyCompress(loadBlockSet().wi.blockRandomisationTable);

		AlienFactory af = new AlienFactory(alienInfoMap);
		List<Alien> aliens = pl.getAliens(af);

		// player start position
		PlayerAlien pa = ListUtil.findOne(PlayerAlien.class, aliens);
		if (pa != null) scr.snapTo(pa.c);

		// load the aliens
		for (Alien alien : aliens) {
			alien.connect(animsPool);
			load(alien);
		}

		// build the AlienPalette
		ArrayList<AlienInfo> ais = new ArrayList<AlienInfo>();
		for (String name : alienInfoMap.queryNames()) {
			ais.add(alienInfoMap.getByName(name));
		}
		alienPalette = new AlienPalette(ais, mgc, animsPool, survey);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		load(alien);
		setSelectedAlien(alien);
		UndoRedo u = new UndoRedo() {
			@Override
			public boolean redo() {
				reinstate(alien);
				setSelectedAlien(alien);
				return true;
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
		alienTracker.add(alien);
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
		mgc.beginDrawing();

		// at();
		// System.exit(1);

		mgc.nextFrame();
		mmp.update(new Coord(mouse.getX(), mouse.getY()), getScreenPosition());

		topDownStatusLayer = new TopDownStatusLayer(mgc);
		bottomUpStatusLayer = new BottomUpStatusLayer(mgc);

		boolean palettes = true;
		int k = keyboard.justPressed();
		// System.out.println(String.format("PRESSED:%08x", k));

		if (!alienMode && keyboard.isDown(Keyboard.KEY_C)) {
			Coord c = mmp.worldBlocksDelta();
			changeCurrentBlock(c.x, c.y);
		}

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
		else {
			if (alienMode) {
				alienMode(k);
			}
			else {
				blockMode(k);
			}

			Coord nc = numCoord(k);
			if (nc != null) {
				setFocus(convertNumCoord(nc));
			}

			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Z) undoControler.undo();
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_Y) undoControler.redo();
			if (k == Keyboard.KEY_ESCAPE) {
				paletteTimer = 0;
				messTimer = 0;
				marker = null;
			}
			if (k == Locks.LOCK_CONTROL + Keyboard.KEY_G) {
				say("Position:" + mmp.worldPixels() + "pixels " + mmp.worldBlocks() + "blocks " + undoControler.size()
						+ "actions");
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
		mgc.endDrawing();

		if (k == Locks.LOCK_MENU + Keyboard.KEY_T) {
			testLevel(false);
		}
		if (k == Locks.LOCK_MENU + Locks.LOCK_SHIFT + Keyboard.KEY_T) {
			testLevel(true);
		}
		if (k == Locks.LOCK_MENU + Keyboard.KEY_S) {
			String levelText = PersistedLevel.staticSave(levelInfo, gameMap, alienTracker);
			TTResource.saveMap(levelInfo.filename, levelText);
			say("Saved: " + levelInfo.filename);
		}
	}

	private Coord convertNumCoord(Coord nc) {
		int x = Math2.fracMult(nc.x, GameMap.MAP_WIDTH * Const.BLOCK_SIZE - 1, 2);
		int y = Math2.fracMult(nc.y, GameMap.MAP_HEIGHT * Const.BLOCK_SIZE - 1, 2);
		Coord c = new Coord(x, y);
		return c;
	}

	private void testLevel(boolean bigTest) {
		String levelText = PersistedLevel.staticSave(levelInfo, gameMap, alienTracker);
		Coord playerPosition = bigTest ? null : mmp.worldPixels();
		World w = new World(ow);
		w.testLevel(bigTest, playerPosition, levelText);
		setScreenPosition(w.getScreenPosition());
	}

	private Coord numCoord(int k) {
		if (k == Keyboard.KEY_NUMPAD7) return new Coord(0, 0);
		if (k == Keyboard.KEY_NUMPAD8) return new Coord(1, 0);
		if (k == Keyboard.KEY_NUMPAD9) return new Coord(2, 0);
		if (k == Keyboard.KEY_NUMPAD4) return new Coord(0, 1);
		if (k == Keyboard.KEY_NUMPAD5) return new Coord(1, 1);
		if (k == Keyboard.KEY_NUMPAD6) return new Coord(2, 1);
		if (k == Keyboard.KEY_NUMPAD1) return new Coord(0, 2);
		if (k == Keyboard.KEY_NUMPAD2) return new Coord(1, 2);
		if (k == Keyboard.KEY_NUMPAD3) return new Coord(2, 2);
		return null;
	}

	private void blockMode(int k) {
		if (k == Pointer.KEY_LEFT) {
			startBlockEdit();
			startPen(k, new Pen() {
				@Override
				public void stroke() {
					edit.setBlock(mmp.worldBlocks(), getCompressedCurrentBlock());
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
			marker = marker == null ? mmp.worldBlocks() : null;
		}
		if (k == Locks.LOCK_CONTROL + Keyboard.KEY_A) {
			marker = new Coord(0, 0);
			setFocus(convertNumCoord(new Coord(2, 2)));
		}
		if (k == Keyboard.KEY_F) {
			if (marker == null) {
				final int blk = gameMap.getBlock(mmp.worldBlocks());
				BlockTest test = new BlockTest() {
					@Override
					public boolean test(int b) {
						return b == blk;
					}
				};
				floodFill(test);
			}
			else {
				fillRect(getCompressedCurrentBlock());
			}
		}

		if (k == Keyboard.KEY_DELETE) fillRect(0);
		if (k == ALIENS_LOCK + Keyboard.KEY_DELETE) {
			if (marker != null) {
				AlienPredicate ap = getRectPredicate();
				removePredicatedAliensWithUndo(ap);
			}
		}
		if (k >= PASTE_BUFFER_START && k <= PASTE_BUFFER_END) {
			int slotNumber = k - PASTE_BUFFER_START;
			if (marker == null) {
				pasteBlocks(slotNumber);
			}
			else {
				copyBlocks(slotNumber);
			}
		}
		if (k >= ALIENS_LOCK + PASTE_BUFFER_START && k <= ALIENS_LOCK + PASTE_BUFFER_END) {
			int slotNumber = k - (ALIENS_LOCK + PASTE_BUFFER_START);
			if (marker == null) {
				pasteAliens(slotNumber);
			}
			else {
				copyAliens(slotNumber);
			}
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

	public AlienPredicate getRectPredicate() {
		final Box rectangle = getRectInPixels();
		return new AlienPredicate() {
			@Override
			public boolean is(Alien a) {
				return rectangle.inside(a.getLocation());
			}
		};
	}

	private Box getRectInBlocks() {
		return Box.fromTwoCorners(mmp.worldBlocks(), marker);
	}

	public Box getRectInPixels() {
		return getRectInBlocks().mult2(Const.BLOCK_SIZE);
	}

	public void removePredicatedAliensWithUndo(final AlienPredicate ap) {
		undoControler.redoThenAdd(new UndoRedo() {
			private List<Alien> lost;

			@Override
			public void undo() {
				for (Alien a : lost) {
					reinstate(a);
				}
			}

			@Override
			public boolean redo() {
				lost = removePredicatedAliens(ap);
				return !lost.isEmpty();
			}
		});
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
				final Coord firstMousePos = mmp.worldPixels();
				final Coord firstBatPos = bat.box().centre();
				final Coord batGrip = firstMousePos.sub2(firstBatPos);
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
						Coord whereSnapped = whereSnapped();
						say("Move by " + whereSnapped.sub2(firstBatPos));
						bat.onMove(whereSnapped);
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
			if (k == Keyboard.KEY_F) setFocus(getSelectedAlien().getLocation());
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
	 *            The position of the origin. <code>null</code> means
	 *            "don't do anything just return the given position unmodified".
	 * @param spokes
	 *            The number of spokes radiating from the origin. The first
	 *            spoke points right and they are equally spaced. e.g. 4 would
	 *            mean "snap to the X and Y axis" while 8 would mean
	 *            "snap to the X and Y axis or the diagonals".
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
		scr.drawGrid(mgc.gc());
		scr.drawBorders(mgc.gc());
		scr.drawTheMap(gameMap, loadBlockSet());
		drawRect();
		updateAliens();
		if (!alienMode) {
			drawBlockCursor();
		}
	}

	private void drawRect() {
		if (marker != null) {
			Box box = getRectInPixels();
			box.shrink(1);
			box.sub(getScreenPosition());
			mgc.drawBox(box.left, box.top, box.width(), box.height(), mgc.process(0xff00ffff));
		}
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
			if (paletteTimer==0) {
				surveyAliens();
			}
			paletteTimer = 100;
		}
	}

	private void surveyAliens() {
		survey.clear();
		for (Alien a: alienTracker) {
			survey.inc(a.alienInfo);
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
		OPS.validate(a);
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
		System.out.println("startBlockEdit");
		assert edit == null;
		edit = new EditConsolidator(gameMap);
	}

	private void endBlockEdit() {
		System.out.println("endBlockEdit");
		assert edit != null;
		submitMapEdit(edit.endEdit());
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

			List<Prop> props = OPS.propsFor(getSelectedAlien());

			// bats
			batRecords.clear();
			for (Prop p : props) {
				p.drawAuxBatStuff(batGc);

				ArrayList<Bat> lbats = new ArrayList<Bat>();
				p.getBats(lbats);
				for (Bat lbat : lbats) {
					batRecords.add(new CommonBatRecord(lbat));
					batGc.drawBat(lbat.box());
				}

			}

			// a super-bat that moves all the alien's visual
			// properties in one go
			final Alien alien = getSelectedAlien();
			BatRecord superBat = new BatRecord() {
				@Override
				public boolean inside(Coord c) {
					return box().inside(c);
				}

				@Override
				public void onMove(Coord c) {
					APS.moveAlienAbsolute(alien, c);
				}

				@Override
				public Box box() {
					return BatGCImpl.boxForSuperBat(alien.getLocation());
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
		List<Alien> all = flatten();
		all.remove(a);
		unflatten(all);
		setSelectedAlien(null);
	}

	private List<Alien> flatten() {
		List<Alien> all = alienTracker.getAll();
		alienTracker = new MapperAlienTracker();
//		APS.orderAlienList(all);
		return all;
	}

	private void unflatten(List<Alien> all) {
		alienTracker.add(all);
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
		alienEdit = new ObjectEdit(a);
	}

	private void endAlienEdit() {
		alienEdit.removeMatching();
		alienEdit.swap();
		undoControler.redoThenAdd(alienEdit);
		alienEdit = null;
	}

	@Override
	public Coord getFocus() {
		return mmp.worldPixels();
	}

	@Override
	public void setFocus(Coord c) {
		setScreenPosition(c.sub2(mmp.screenPixels()));
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
			public boolean redo() {
				deleteAlien(a);
				return true;
			}
		});
	}

	private void copySelectedAlien() {
		final Alien src = getSelectedAlien();
		if (!src.alienInfo.internal()) {
			Alien dest = copyAlien(src);
			APS.moveAlienAbsolute(dest, mmp.worldPixels());
			createAlienWithUndoRedo(dest);
		}
	}

	private Alien copyAlien(Alien src) {
		Alien dest = makeAlien(src.alienInfo);
		dest.connect(src);
		OPS.copyProps(src, dest);
		return dest;
	}

	private void submitMapEdit(MapEdit u) {
		undoControler.redoThenAdd(u);
	}

	public void pasteAliens(int slotNumber) {
		SavedAlienSlot sas = alienSlots[slotNumber];
		if (sas != null) {
			undoControler.mark();
			Coord oc = sas.corner;
			Coord nc = mmp.worldBlocks().mul2(Const.BLOCK_SIZE);
			Coord diff = nc.sub2(oc);
			for (Alien a : sas.aliens) {
				Alien a2 = copyAlien(a);
				APS.moveAlienRelative(a2, diff);
				createAlienWithUndoRedo(a2);
			}
			undoControler.fold();
			say("Pasted " + sas.aliens.size() + " aliens from slot " + slotNumber);
		}
	}

	public void pasteBlocks(int slotNumber) {
		SavedMapBlock slot = blockSlots[slotNumber];
		if (slot != null) {
			Coord c = mmp.worldBlocks();
			// does it fit?
			boolean itFits = c.x + slot.w <= GameMap.MAP_WIDTH && c.y + slot.h <= GameMap.MAP_HEIGHT;
			if (itFits) {
				// paste it!
				MapEdit edit = MapEdit.create(gameMap, c, slot.copy());
				submitMapEdit(edit);
			}
			say("Pasted " + slot.size() + " blocks from slot " + slotNumber);
		}
	}

	public void copyAliens(int slotNumber) {
		Box rectangle = getRectInBlocks();
		rectangle.mult(Const.BLOCK_SIZE);
		List<Alien> captured = new ArrayList<Alien>();
		for (Alien a : alienTracker) {
			if (rectangle.inside(a.getLocation())) {
				captured.add(copyAlien(a));
			}
		}
		alienSlots[slotNumber] = new SavedAlienSlot(rectangle.topLeft(), captured);
		say("Copied " + captured.size() + " aliens to slot " + slotNumber);
	}

	public void copyBlocks(int slotNumber) {
		Box rectangle = getRectInBlocks();
		SavedMapBlock s = SavedMapBlock.fromMap(rectangle, gameMap);
		blockSlots[slotNumber] = s;
		say("Copied " + s.size() + " blocks to slot " + slotNumber);
	}

	private void fillRect(int block) {
		Box rectangle = getRectInBlocks();
		SavedMapBlock s = SavedMapBlock.fromSolid(rectangle.width(), rectangle.height(), block);
		MapEdit edit = MapEdit.create(gameMap, rectangle.topLeft(), s);
		submitMapEdit(edit);
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

	public Coord getScreenPosition() {
		return scr.position();
	}

	public void setScreenPosition(Coord c) {
		scr.setPosition(c);
	}

	private void updateAliens() {
		Box screenBox = scr.box();
		alienTracker.begin(screenBox);
		List<Alien> a = alienTracker.getOnScreen();
		updateList(a, Alien.DEPTH_BG_SCENARY, screenBox);
		updateList(a, Alien.DEPTH_LIFTS_AND_COLLECTABLES, screenBox);
		updateList(a, Alien.DEPTH_ALIENS, screenBox);
		updateList(a, Alien.DEPTH_FG_SCENARY, screenBox);
	}

	private void updateList(List<Alien> alienList, int depth, Box screenBox) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			if (alien.depth == depth) {
				alien.freezeBounds = null;
				alien.mapperUpdate();
				if (alienTracker.perhapsFreeze(alien, screenBox)) {
					alienIterator.remove();
				}
			}
		}
	}

	public Anim mapperLoadAnim(String animsName) {
		Anims anims = animsPool.expect(animsName);
		Anim anim = anims.find(0);
		return anim;
	}

	public Alien findNearestAlien(Coord c) {
		long dist = Long.MAX_VALUE;
		Alien answer = null;
		for (Alien a : alienTracker) {
			Coord diff = a.getLocation().sub2(c);
			long ndist = diff.squareOfLength();
			if (ndist < dist) {
				dist = ndist;
				answer = a;
			}
		}
		return answer;
	}

	public BlockSet loadBlockSet() {
		return ow.loadBlockSet(new BlockSet.Config(worldName, seeMasks, seeHidden));
	}

	public void reinstate(Alien alien) {
		alienTracker.add(alien);
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
		int b = gameMap.safeGetBlock(coord.copyAndAdd(i, j));
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
		positions.add(mmp.worldBlocks());

		while (!positions.isEmpty()) {
			ArrayList<Coord> nextPositions = new ArrayList<Coord>();
			for (Coord s : positions) {
				if (!edit.isChangeAt(s) && fillable.test(gameMap.safeGetBlock(s))) {
					edit.setBlock(s, getCurrentBlock());
					nextPositions.add(s.copyAndAdd(1, 0));
					nextPositions.add(s.copyAndAdd(-1, 0));
					nextPositions.add(s.copyAndAdd(0, 1));
					nextPositions.add(s.copyAndAdd(0, -1));
				}
			}
			positions = nextPositions;
		}

		say(edit.size() + " blocks filled");
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

				boolean checkers = Math2.maskTest(x ^ y, 1);

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
						if (wallNorth) v |= 1;
						if (wallNorthWest) v |= 2;
						if (wallWest) v |= 4;
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

						if (n >= 0) {
							// n += 167;
							n += 160;
							// n += 80;
							// n += 87;
							if (!checkers) {
								n += 40;
							}
							if (wallSouth) {
								n += 20;
							}
						}
						else {
							System.out.println("Bad wall placement: " + b + " at " + coord);
						}
					}
					if (n < 0) System.out.println("Mystery space: " + b + " at " + coord);
				}
				else if (b == 0) {

				}
				else {
					System.out.println("Something else: " + b + " at " + coord);
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
		System.out.println("Done! Correct:" + pc + " wrong:" + pw);
	}

	public void run() {
		for (;;) {
			drawFrame();
		}
	}

	public List<Alien> removePredicatedAliens(AlienPredicate ap) {
		List<Alien> lost = new ArrayList<Alien>();
		List<Alien> as = flatten();
		for (Iterator<Alien> iterator = as.iterator(); iterator.hasNext();) {
			Alien alien = iterator.next();
			if (ap.is(alien)) {
				iterator.remove();
				lost.add(alien);
			}
		}
		unflatten(as);
		return lost;
	}
}
