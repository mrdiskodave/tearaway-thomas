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
import com.nney.tt.LevelInfo;
import com.nney.tt.OuterWorld;
import com.nney.tt.PersistedLevel;
import com.nney.tt.PlayerPosition;
import com.nney.tt.PlayerPositionServices;
import com.nney.tt.ScreenPosition;
import com.nney.tt.World;
import com.nney.tt.aliens.Alien;
import com.nney.tt.aliens.AlienWithLocation;
import com.nney.tt.aliens.GemAlien;
import com.nney.tt.aliens.LegacyAlien;
import com.nney.tt.aliens.PlayerAlien;
import com.nney.tt.geom.Box;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.HasKeys;
import com.nney.tt.input.KeyEvent;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Locks;
import com.nney.tt.input.LocksKeyAdaptor;
import com.nney.tt.input.Pointer;
import com.nney.tt.input.TeeKeyAdaptor;
import com.nney.tt.map.GameMap;
import com.nney.tt.mapper.StringEditor.State;
import com.nney.tt.props.Bat;
import com.nney.tt.props.Button;
import com.nney.tt.props.ButtonPressServices;
import com.nney.tt.props.HasProps;
import com.nney.tt.props.OPS;
import com.nney.tt.props.Prop;
import com.nney.tt.props.TakeTextBack;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.Anim;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;
import com.nney.tt.tinytools.SlowBoolean;
import com.nney.utils.CountingMap;
import com.nney.utils.ListUtil;
import com.nney.utils.Math2;
import com.nney.utils.SortKeyGenerator;

/**
 * A level editor.
 * 
 * <pre>
 * [A] Alien Mode:
 *   [RMB] near an alien to select alien - buttons and control points appear! 
 *   [LMB] on a control point to grab and drag it
 *         press [SHIFT] to constrain dragging to axises
 *   [CURSOR KEYS] on a control point to nudge it
 *   [LMB] on a button to press it
 *   [C] copy the selected alien
 *   [PAGEUP/PAGEDOWN] change current alien type
 *   [Q] show (query) the current alien type 
 *   [I] eye dropper - sets the current alien type from the selected alien 
 *   [N] create a new alien (of the current alien type)
 *   [DELETE] delete the selected alien
 *   [F] find: jump to the selected alien
 *   [NUMPAD+/-] jump to the next/previous occurrence of the current alien type
 * 
 * [D] Drawing Mode:
 *   [LMB] draw with the current block
 *   [I] eye dropper - sets the current block from the map
 *   [CURSOR KEYS] change the current block
 *   [Q] show (query) the current block without changing it 
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
 *   work on aliens instead of blocks when you hold down Ctrl
 *   (i.e. every slot can hold blocks, aliens or both).
 *   
 *   [Ctrl+A] start marking a rectangle of blocks covering the whole map
 *            (this requires a jump to the bottom right of the map)
 *   [Ctrl+M] toggle seeing block masks
 *   [Ctrl+H] toggle seeing hidden blocks
 *   {Ctrl+G] toggle seeing the grid
 *   [Ctrl+Alt+Shift+C] capture a legacy toyland level
 *   (by renumbering all the blocks into the new system)
 * 
 *   hold [RMB] for full screen block chooser:
 *     [LMB] to pick.
 *     [CURSOR KEYS], [CTRL+M] and [CTRL+I] work in here too
 *     
 * [S] Specification mode:
 *   Level properties are displayed (e.g. level title e.g. horizon number)
 *   and they can be set in the same way as the properties of aliens durnig
 *   Alien Mode.
 * 
 * Always:
 * hold [SPACE] to pan around with the [LMB] (hold [SHIFT] to go faster)
 * [NUMPAD5] jump to the middle of the level
 *           (and the eight numbered keys around it work as expected)
 * [Ctrl+W] where am I?
 * [Ctrl+Z] endless undo
 * [Ctrl+Y] endless redo
 * [ESCAPE] reset
 *          (removes temporary floating palettes and other statefulness)
 * [Alt+T] small test (test the level from the mouse position without the intro)
 * [Alt+Shift+T] big test (test the whole level as the player would experience it)
 * [Alt+S] save the level
 * 
 * Notes:
 * The editor never moves the mouse pointer. This means "jump" operations above
 * just place the jumped-to-location under the mouse pointer. If you
 * are making heavy use of jumping you'll get less dizzy if you place the
 * mouse pointer in the middle of the screen.
 * </pre>
 */
public class Mapper implements ButtonPressServices {
	static public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	private static final int KEY_SELECT_ALL = Locks.LOCK_CONTROL + Keyboard.KEY_A;

	private static final int KEY_REDO = Locks.LOCK_CONTROL + Keyboard.KEY_Y;

	private static final int KEY_UNDO = Locks.LOCK_CONTROL + Keyboard.KEY_Z;

	private static final int KEY_WHERE = Locks.LOCK_CONTROL + Keyboard.KEY_W;

	private static final int KEY_SEE_GRID = Locks.LOCK_CONTROL + Keyboard.KEY_G;

	private static final int KEY_SEE_HIDDEN = Locks.LOCK_CONTROL + Keyboard.KEY_H;

	private static final int KEY_SEE_MASKS = Locks.LOCK_CONTROL + Keyboard.KEY_M;

	private static final int ALIENS_LOCK = Locks.LOCK_CONTROL;

	// prop panel layout:

	private static final int PROPS_FIRST_LINE = 2;

	private static final int PROPS_X_NAME = 0;

	private static final int PROPS_X_VALUE = 15;

	private static final int PROPS_X_BUTTONS = 45;

	private static final int PROPS_W_NAME = PROPS_X_VALUE - PROPS_X_NAME;

	private static final int PROPS_W_VALUE = PROPS_X_BUTTONS - PROPS_X_VALUE;

	interface AlienPredicate {
		boolean is(Alien t);
	}

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

	private EditConsolidator blockEdit;

	private final CollidableList<BatRecord> batRecords = new CollidableList<BatRecord>();
	private final CollidableList<ButtonRecord> buttonRecords = new CollidableList<ButtonRecord>();
	private List<Prop> props;

	private ObjectEdit alienEdit;

	private final HoverStatus<ButtonRecord> hoverStatus = new HoverStatus<ButtonRecord>();
	private Alien selectedAlien;

	private final MapperMousePosition mmp;

	private StatusLayer topDownStatusLayer;

	private final UndoControler undoControler = new UndoControler();

	private final HasKeys keyboard;

	private Runnable pen;

	private Coord marker;

	enum Mode {
		DRAW, ALIEN, SPECIFICATION, PLAYERSIMULATION
	}

	private Mode mode = Mode.DRAW;

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

	static final int FLAG_SEE_HIDDEN = 1;
	static final int FLAG_SEE_MASKS = 2;
	static final int FLAG_SEE_GRID = 4;

	int flags = FLAG_SEE_HIDDEN + FLAG_SEE_GRID;

	private MapperAlienTracker alienTracker = new MapperAlienTracker();

	private final AlienServices alienServices = new MapperAlienServices(this);

	private BottomUpStatusLayer bottomUpStatusLayer;

	private LevelInfo levelInfo;

	private Prop mouseOver;

	private EditManager editManager;

	private SlowBoolean editManagerStartObjectEdit = new SlowBoolean();

	private Box constraints;

	private PlayerPosition sim;

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

		keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(ow.mouse, ow.keyboard));
		mouse = ow.mouse;
		animsPool = ow.animsPool;

		PersistedLevel pl = new PersistedLevel(ow.levelNumber, null);
		levelInfo = pl.getLevelInfo();
		// AlienInfoMap must be bent around so that we can load all
		// the aliens, find LevelInfoAlien, and ONLY THEN set the worldName
		// into the infoMap.
		alienInfoMap = new AlienInfoMap(levelInfo.worldName, alienServices);

		for (String a : alienInfoMap.queryAnimList()) {
			animsPool.load(a);
		}

		gameMap = pl.getMap();
		constraints = gameMap.boundsInPixels();
		loadBlockSet().compressMap(gameMap);

		Box mapBoundsInPixels = gameMap.boundsInPixels();
		mmp = new MapperMousePosition(mapBoundsInPixels);
		Box scrollBounds = mapBoundsInPixels.copy();
		int w = mgc.screenWidth() - 1;
		int h = mgc.screenHeight() - 1;
		scrollBounds.left -= w;
		scrollBounds.top -= h;
		scrollBounds.right += w;
		scrollBounds.bottom += h;
		scr.setMapBoundsInPixels(scrollBounds, mapBoundsInPixels);

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
		List<AlienInfo> ais = alienInfoMap.getExternal();
		alienPalette = new AlienPalette(ais, mgc, animsPool);
		sendCensusToAlienPalette();
	}

	void createAlienWithUndoRedo(final Alien alien) {
		OPS.validate(alien, constraints);
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

	public void drawFrame() {
		mgc.beginDrawing();

		// at();
		// System.exit(1);

		mmp.update(new Coord(mouse.getX(), mouse.getY()), getScreenPosition());

		topDownStatusLayer = new TopDownStatusLayer(mgc);
		bottomUpStatusLayer = new BottomUpStatusLayer(mgc);

		if (editManager != null) {
			if (editManagerStartObjectEdit.set(false)) {
				startObjectEdit();
			}
			drawLevel();
			drawOverlays();
			KeyEvent e = keyboard.nextEvent();
			if (e != null) {
				editManager.keyboardInput(e);
				if (e.keyCode == Keyboard.KEY_RETURN) {
					editManager.done();
					endObjectEdit();
					editManager = null;
				}
			}
			mgc.endDrawing();
			return;
		}

		boolean showPalettes = true;

		KeyEvent e = keyboard.nextEvent();
		int k = e == null ? 0 : e.keyCode;

		if (mode == Mode.DRAW && keyboard.isDown(Keyboard.KEY_C)) {
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
		else if (mode == Mode.DRAW && keyboard.isDown(Pointer.KEY_RIGHT)) {
			blockSelectionKeys(k);
			blockChoosingMode();
			showPalettes = false;
		}
		else {
			if (mode == Mode.ALIEN) alienMode(k);
			if (mode == Mode.DRAW) drawMode(k);
			if (mode == Mode.SPECIFICATION) specificationMode(k);
			if (mode == Mode.PLAYERSIMULATION) simulationMode(k);
			changeMode(k);

			Coord nc = numCoord(k);
			if (nc != null) {
				moveMouse(convertNumCoord(nc));
			}
			if (k == KEY_WHERE) {
				where(true);
			}

			if (k == KEY_UNDO) undoControler.undo();
			if (k == KEY_REDO) undoControler.redo();
			if (k == Keyboard.KEY_ESCAPE) {
				paletteTimer = 0;
				messTimer = 0;
				marker = null;
			}
			drawLevel();
		}

		if (showPalettes) {
			drawOverlays();
		}
		mgc.endDrawing();

		if (k == Locks.LOCK_MENU + Keyboard.KEY_T) {
			testLevel(false);
		}
		if (k == Locks.LOCK_MENU + Locks.LOCK_SHIFT + Keyboard.KEY_T) {
			testLevel(true);
		}
		if (k == Locks.LOCK_MENU + Keyboard.KEY_S) {
			int playerCount = ListUtil.count(PlayerAlien.class, alienTracker);
			if (playerCount != 1) {
				sayf("Can't save an invalid map: needs one player (not %s)", playerCount);
			}
			else {
				saveMap(false);
				sayf("Saved: %s", levelInfo.filename);
				undoControler.saved();
			}
		}

		if (Math2.maskTest(k, Locks.LOCK_MENU)) {
			int pureKey = k & (~Locks.LOCK_ALL);
			int sl = Locks.LOCK_CONTROL | Locks.LOCK_SHIFT;
			boolean sure = (k & sl) == sl;

			if (pureKey == Keyboard.KEY_Q && mustBeSure(sure, "Quit")) {
				throw new OuterWorld.ExitException();
			}
			if (pureKey == Keyboard.KEY_N && !ow.lastLevel() && mustBeSure(sure, "Next level")) {
				ow.levelNumber++;
				throw new ExitException();
			}
			if (pureKey == Keyboard.KEY_P && !ow.firstLevel() && mustBeSure(sure, "Previous level")) {
				ow.levelNumber--;
				throw new ExitException();
			}
		}

		if (k == Locks.LOCK_MENU + Keyboard.KEY_E) {
			// enliven
			List<Alien> all = flatten();
			List<Alien> n = new ArrayList<Alien>();
			int count = 0;
			for (Iterator<Alien> iterator = all.iterator(); iterator.hasNext();) {
				Alien a = iterator.next();
				if (a instanceof LegacyAlien) {
					count++;
					LegacyAlien la = (LegacyAlien) a;
					byte[] d = la.getLegacyData();

					int typeCode = d[0] & 0xff;
					String tcName = AlienInfoMap.typeCodeToName(typeCode);
					System.out.println("Enliven: " + tcName);
					if (alienInfoMap.nameExists(tcName)) {
						System.out.println("yes");
						Alien alien = alienInfoMap.instantiateAttach(alienInfoMap.getByName(tcName));
						if (alien instanceof AlienWithLocation) {
							AlienWithLocation awl = (AlienWithLocation) alien;
							awl.c = la.getLocation();
						}
						alien.legacyData = d;
						alien.loadFromLegacyData();
						alien.connect(animsPool);
						n.add(alien);
						iterator.remove();
					}
				}
			}
			sayf("%s out of %s legacy aliens enlivened", n.size(), count);
			ListUtil.copy(all, n);
			unflatten(all);
		}
	}

	private void where(boolean more) {
		int u = countAliens(LegacyAlien.class);
		int g = countAliens(GemAlien.class);
		String s = String.format("Level: %s %s | Gems: %s", ow.levelNumber, levelInfo.filename, g);
		if (u != 0) {
			s += String.format(" | Legacy: %s", u);
		}
		if (more) {
			s += String.format(" | Position: %spixels %sblocks | Changes made: %s", mmp.worldPixels(),
					mmp.worldBlocks(), undoControler.changes());
		}
		say(s);
	}

	public int countAliens(Class<? extends Alien> t) {
		return ListUtil.count(t, alienTracker);
	}

	private boolean mustBeSure(boolean sure, String task) {
		int changes = undoControler.changes();
		if (sure || changes == 0) return true;
		sayf("%s: Abandon %s unsaved changes? +Ctrl+Shift if certain", task, changes);
		return false;
	}

	public void drawOverlays() {
		if (mode == Mode.ALIEN) drawProps();
		if (mode == Mode.SPECIFICATION) {
			drawProps();
		}
		if (mode == Mode.PLAYERSIMULATION) {
			Coord c = sim.get().sub2(getScreenPosition());
			mgc.drawSight(c.x, c.y, 40, sim.isStanding() ? 0xff00ff00 : 0xffff0000);
		}
		drawPalettes();

		if (messTimer != 0) {
			messTimer--;
			bottomUpStatusLayer.draw(0, 0, messText);
		}
	}

	public void saveMap(boolean autoSave) {
		String levelText = PersistedLevel.staticSave(levelInfo, gameMap, alienTracker);
		TTResource.saveMap(levelInfo.filename, levelText, autoSave);
	}

	private Coord convertNumCoord(Coord nc) {
		int x = Math2.fracMult(nc.x, gameMap.width() * Const.BLOCK_SIZE - 1, 2);
		int y = Math2.fracMult(nc.y, gameMap.height() * Const.BLOCK_SIZE - 1, 2);
		Coord c = new Coord(x, y);
		return c;
	}

	private void testLevel(boolean bigTest) {
		saveMap(true);

		World w = new World(ow);
		if (!bigTest) {
			w.configurePerformIntro(false);
			w.configurePlayerStart(mmp.worldPixels());
			// w.configureScriptRecording(levelInfo.filename);
			w.configureSeeHidden(testFlag(FLAG_SEE_HIDDEN));
			w.configureSeeMasks(testFlag(FLAG_SEE_MASKS));
		}
		w.configureMapText(PersistedLevel.staticSave(levelInfo, gameMap, alienTracker));
		w.testLevelFromMapper();
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

	private void drawMode(int k) {
		if (k == Pointer.KEY_LEFT) {
			startBlockEdit();
			startPen(k, new Pen() {
				@Override
				public void stroke() {
					blockEdit.setBlock(mmp.worldBlocks(), getCompressedCurrentBlock());
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
		if (k == KEY_SELECT_ALL) {
			marker = new Coord(0, 0);
			moveMouse(convertNumCoord(new Coord(2, 2)));
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
		if (k == ALIENS_LOCK + Keyboard.KEY_DELETE && marker != null) {
			removePredicatedAliensWithUndo(getRectPredicate());
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

		if (k == Locks.LOCK_ALL + Keyboard.KEY_C) {
			loadBlockSet().legacyCapture(gameMap);
		}
	}

	public void changeMode(int k) {
		if (changeMode(k, Keyboard.KEY_A, Mode.ALIEN, "Alien Mode")) {
			generateButtons(selectedAlien);
		}
		changeMode(k, Keyboard.KEY_D, Mode.DRAW, "Drawing Mode");
		if (changeMode(k, Keyboard.KEY_S, Mode.SPECIFICATION, "Specification Mode")) {
			generateButtons(levelInfo);
		}
		if (changeMode(k, Keyboard.KEY_P, Mode.PLAYERSIMULATION, "Player Simulation Mode")) {
			simulationModeInit();
		}
	}

	private boolean changeMode(int k, int r, Mode m, String d) {
		boolean answer = mode != m && k == r;
		if (answer) {
			mode = m;
			marker = null;
			paletteTimer = 0;
			say(d);
		}
		return answer;
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
		assert marker != null;
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

	private void findType(int dir) {
		ArrayList<Alien> candidates = new ArrayList<Alien>();
		AlienInfo t = alienPalette.get();
		for (Alien a : alienTracker) {
			if (a.alienInfo == t) {
				candidates.add(a);
			}
		}
		ListUtil.sort(candidates, new SortKeyGenerator<Alien, Coord>() {
			@Override
			public Coord gen(Alien t) {
				return t.getLocation();
			}
		});
		if (candidates.size() != 0) {
			int z = candidates.indexOf(getSelectedAlien());
			if (z < 0) {
				z = 0;
			}
			else {
				z += candidates.size() + dir;
				z %= candidates.size();
			}
			Alien a = candidates.get(z);
			setSelectedAlien(a);
			moveMouse(a.getLocation());
			sayf("%s %d of %d", t.name, z + 1, candidates.size());
		}
		else {
			sayf("%s not found", t.name);
		}
	}

	private void specificationMode(int k) {
		ButtonRecord button = findButton();
		hoverStatus.move(button);
		checkPropMouseOver();
		if (k == Pointer.KEY_LEFT && button != null) {
			handleButtonPress(k, button);
		}
	}

	public void simulationModeInit() {
		sim = new PlayerPosition(mmp.worldPixels(), new PlayerPositionServices() {
			@Override
			public boolean inTheGround(int x, int y) {
				int block = gameMap.fastGetBlock(x >> Const.BLOCK_SHIFT, y >> Const.BLOCK_SHIFT);
				return loadBlockSet().maskHolder.inTheGround(block, x & Const.BLOCK_MASK, y & Const.BLOCK_MASK);
			}
		});
	}

	private void simulationMode(int k) {
		flagSelectionKeys(k);

		if (keyboard.isDown(Pointer.KEY_LEFT)) {
			Coord d = mmp.worldPixels();
			Coord s = sim.get();
			Coord diff = d.sub2(s);
			diff.signum();
			simDiff(diff);
		}

		if (k == Pointer.KEY_RIGHT) {
			simulationModeInit();
		}

		Coord diff = getNudge(k);
		if (diff != null) simDiff(diff);
	}

	public void simDiff(Coord diff) {
		Coord c = sim.get().copy();
		sim.move(diff.x, diff.y);
		if (!sim.get().equals(c)) {
			System.out.println("Now at " + sim.get());
		}
	}

	private void alienMode(int k) {
		checkPropMouseOver();

		if (k == Pointer.KEY_RIGHT) {
			startPen(k, new Pen() {
				@Override
				void stroke() {
					selectNearestAlien(mmp.worldPixels());
				}
			});
		}

		final BatRecord bat = batRecords.find(mmp.worldPixels());
		int kns = k & (~Locks.LOCK_SHIFT);

		ButtonRecord button = findButton();
		hoverStatus.move(button);

		if (kns == Pointer.KEY_LEFT) {
			if (button != null && k == kns) {
				handleButtonPress(k, button);
			}
			else if (bat != null) {
				final Coord firstMousePos = mmp.worldPixels();
				final Coord firstBatPos = bat.box().centre();
				final Coord batGrip = firstMousePos.sub2(firstBatPos);
				final HasProps a = getSelectedAlien();
				startObjectEdit();
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
						sayf("Move by %s", whereSnapped.sub2(firstBatPos));
						bat.onMove(whereSnapped);
						validateAlien(a);
					}

					@Override
					public void up() {
						endObjectEdit();
					}
				});
			}
		}
		else {
			Coord nudge = getNudge(k);
			if (nudge != null && bat != null) {
				startObjectEdit();
				Coord firstBatPos = bat.box().centre();
				nudge.add(firstBatPos);
				bat.onMove(nudge);
				endObjectEdit();
			}
		}
		if (haveAlien()) {
			if (k == Keyboard.KEY_DELETE) deleteSelectedAlien();
			if (k == Keyboard.KEY_C) copySelectedAlien();
			if (k == Keyboard.KEY_F) moveMouse(getSelectedAlien().getLocation());
		}
		if (k == Keyboard.KEY_ADD) findType(1);
		if (k == Keyboard.KEY_SUBTRACT) findType(-1);
		if (k == Keyboard.KEY_N) createAlien();
		keyboardAlienChoice(k);
		flagSelectionKeys(k);
	}

	public void checkPropMouseOver() {
		mouseOver = null;
		if (props != null) {
			int y = PROPS_FIRST_LINE;
			for (Prop p : props) {
				if (topDownStatusLayer.getBox(0, y++, -1, 1).inside(mmp.screenPixels())) {
					mouseOver = p;
				}
			}
		}
	}

	public void handleButtonPress(int k, ButtonRecord button) {
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
					startObjectEdit();
					b.press();
					endObjectEdit();
				}
			}
		});
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
			if (mode == Mode.ALIEN) alienPalette.showAlienPalette();
			if (mode == Mode.DRAW) makeBP().showSmallPalette(getCurrentBlock());
		}
	}

	private void drawLevel() {
		if (testFlag(FLAG_SEE_GRID)) {
			mgc.fillRectangle(0, 0, mgc.screenWidth(), mgc.screenHeight(), COL_BACKGROUND);
			scr.drawGrid(mgc.gc());
		}
		else {
			ow.getHorizon(levelInfo.horizon).draw();
		}
		scr.drawBorders(mgc.gc());
		scr.drawTheMap(gameMap, loadBlockSet());
		drawRect();
		updateAliens();
		if (mode == Mode.DRAW) {
			drawBlockCursor();
		}
	}

	private boolean testFlag(int test) {
		return Math2.maskTest(flags, test);
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

	private void sayf(String f, Object... a) {
		say(String.format(f, a));
	}

	private void keyboardAlienChoice(int k) {
		if (k == Keyboard.KEY_Q) {
			showAlienPalette();
		}
		if (k == Keyboard.KEY_NEXT) {
			showAlienPalette();
			alienPalette.next();
		}
		if (k == Keyboard.KEY_PRIOR) {
			showAlienPalette();
			alienPalette.prev();
		}
		if (k == Keyboard.KEY_I && haveAlien()) {
			showAlienPalette();
			alienPalette.find(getSelectedAlien().alienInfo);
		}
	}

	public void showAlienPalette() {
		if (paletteTimer == 0) {
			sendCensusToAlienPalette();
		}
		paletteTimer = 100;
	}

	public void sendCensusToAlienPalette() {
		CountingMap<AlienInfo> census = new CountingMap<AlienInfo>();
		for (Alien a : alienTracker) {
			census.inc(a.alienInfo);
		}
		alienPalette.sendCenus(census);
	}

	private Alien makeAlien(AlienInfo ai) {
		return alienInfoMap.instantiateAttach(ai);
	}

	private void createAlien() {
		AlienInfo ai = alienPalette.get();
		Alien a = makeAlien(ai);
		a.resetTo(mmp.worldPixels());
		a.connect(animsPool);
		createAlienWithUndoRedo(a);
	}

	void blockSelectionKeys(int k) {
		if (k == Keyboard.KEY_Q) changeCurrentBlock(0, 0);
		if (k == Keyboard.KEY_UP) changeCurrentBlock(0, -1);
		if (k == Keyboard.KEY_DOWN) changeCurrentBlock(0, 1);
		if (k == Keyboard.KEY_LEFT) changeCurrentBlock(-1, 0);
		if (k == Keyboard.KEY_RIGHT) changeCurrentBlock(1, 0);
		flagSelectionKeys(k);
	}

	public void flagSelectionKeys(int k) {
		if (k == KEY_SEE_MASKS) flipFlag(FLAG_SEE_MASKS);
		if (k == KEY_SEE_HIDDEN) flipFlag(FLAG_SEE_HIDDEN);
		if (k == KEY_SEE_GRID) flipFlag(FLAG_SEE_GRID);
	}

	private void flipFlag(int flip) {
		flags ^= flip;
		sayf("Masks: %s | Hidden Blocks: %s | Grid: %s", testFlagAsString(FLAG_SEE_MASKS),
				testFlagAsString(FLAG_SEE_HIDDEN), testFlagAsString(FLAG_SEE_GRID));
	}

	private String testFlagAsString(int test) {
		return testFlag(test) ? "ON " : "OFF";
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
		assert blockEdit == null;
		blockEdit = new EditConsolidator(gameMap);
	}

	private void endBlockEdit() {
		System.out.println("endBlockEdit");
		assert blockEdit != null;
		submitMapEdit(blockEdit.endEdit());
		blockEdit = null;
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
		generateButtons(s);
	}

	public void generateButtons(HasProps s) {
		props = null;
		buttonRecords.clear();
		if (s != null) {
			// build buttonRecords!
			props = OPS.propsFor(s);
			int y = PROPS_FIRST_LINE;
			StatusLayer sl = topDownStatusLayer;
			for (Prop p : props) {
				int x = PROPS_X_BUTTONS;
				ArrayList<Button> buttons = new ArrayList<Button>();
				p.getButtons(buttons, this);
				for (Button button : buttons) {
					String buttonText = buttonLabel(button);
					Box buttonBox = sl.getBox(x, y, buttonText);
					buttonRecords.add(new ButtonRecord(button, buttonBox, buttonText, new Coord(x, y)));
					x += buttonText.length() + 1;
				}
				y++;
			}
		}
	}

	@Override
	public void startEdit(Prop prop, String initialValue, TakeTextBack textBack) {
		// we're inside an objectEdit right now
		// (as there is a button press going on and
		// we might have wanted to change the given prop)
		// instead we set up the editManager
		editManager = new EditManager(prop, new StringEditor(initialValue, PROPS_W_VALUE), textBack);
		// and set a flag for deferred startObjectEdit() when
		// we encounter the new EditManager for the first time
		editManagerStartObjectEdit.set(true);
	}

	public void drawProps() {
		if (props == null) return;

		//
		// bats
		//

		BatGCImpl batGc = new BatGCImpl(getScreenPosition(), mgc);

		if (mode == Mode.ALIEN) {
			batGc.drawSuperBat(getSelectedAlien().getLocation());
		}

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

		if (mode == Mode.ALIEN) {
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
		}

		//
		// property descriptions
		//
		StatusLayer sl = topDownStatusLayer;
		int y = 0;
		while (y < PROPS_FIRST_LINE) {
			sl.touch(y++);
		}

		for (Prop p : props) {
			if (p == mouseOver) {
				sl.highlightTouch(y);
			}

			sl.draw(PROPS_X_NAME, y, clip(p.name(), PROPS_W_NAME));
			if (editManager != null && editManager.isUs(p)) {
				State s = editManager.state();
				if (editManager.isCursorOn()) {
					sl.drawWithCursor(PROPS_X_VALUE, y, s.cursor, s.show);
				}
				else {
					sl.draw(PROPS_X_VALUE, y, s.show);
				}
			}
			else {
				sl.draw(PROPS_X_VALUE, y, clip(p.text(), PROPS_W_VALUE));
			}
			y++;
		}

		//
		// buttons
		//
		for (ButtonRecord b : buttonRecords) {
			sl.draw(b.position.x, b.position.y, hoverStatus.status(b), b.label);
		}
		//
		// docs
		//
		if (mouseOver != null) {
			sl.draw(0, 0, mouseOver.doc());
		}
	}

	public String buttonLabel(Button button) {
		return "[" + button.name() + "]";
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
		// APS.orderAlienList(all);
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

	private void startObjectEdit() {
		assert alienEdit == null;
		HasProps a = getSelectedObject();
		alienEdit = new ObjectEdit(a);
	}

	private void endObjectEdit() {
		HasProps a = getSelectedObject();
		validateAlien(a);
		alienEdit.removeMatching();
		alienEdit.swap();
		undoControler.redoThenAdd(alienEdit);
		alienEdit = null;
	}

	private HasProps getSelectedObject() {
		if (mode == Mode.ALIEN) return getSelectedAlien();
		if (mode == Mode.SPECIFICATION) return levelInfo;
		assert false;
		return null;
	}

	public void validateAlien(HasProps a) {
		OPS.validate(a, constraints);
		a.onPropUpdate();
	}

	@Override
	public Coord getFocus() {
		return getScreenPosition().add2(screenMid());
	}

	@Override
	public void setFocus(Coord c) {
		setScreenPosition(c.sub2(screenMid()));
	}

	private Coord screenMid() {
		return new Coord(mgc.screenWidth() / 2, mgc.screenHeight() / 2);
	}

	// we can't actually move the mouse
	// so we scroll the required spot on the map
	// to be under the mouse
	public void moveMouse(Coord c) {
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
		assert u != null;
		undoControler.redoThenAdd(u);
	}

	public void pasteAliens(int slotNumber) {
		SavedAlienSlot slot = alienSlots[slotNumber];
		if (slot != null) {
			undoControler.mark();
			Coord oc = slot.corner;
			Coord nc = mmp.worldBlocks().mul2(Const.BLOCK_SIZE);
			Coord diff = nc.sub2(oc);
			for (Alien a : slot.aliens) {
				Alien a2 = copyAlien(a);
				APS.moveAlienRelative(a2, diff);
				createAlienWithUndoRedo(a2);
			}
			undoControler.fold();
			sayf("Pasted %s aliens from slot %s", slot.aliens.size(), slotNumber);
		}
	}

	public void pasteBlocks(int slotNumber) {
		SavedMapBlock slot = blockSlots[slotNumber];
		if (slot != null) {
			Coord c = mmp.worldBlocks();
			// does it fit?
			int xs = c.x + slot.w - gameMap.width();
			int ys = c.y + slot.h - gameMap.height();
			if (xs > 0) {
				sayf("Move left by at least %s blocks", xs);
			}
			else if (ys > 0) {
				sayf("Move up by at least %s blocks", ys);
			}
			else {
				// paste it!
				MapEdit edit = MapEdit.create(gameMap, c, slot.copy());
				submitMapEdit(edit);
				sayf("Pasted %s blocks from slot %s", slot.size(), slotNumber);
			}
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
		sayf("Copied %s aliens to slot %s", captured.size(), slotNumber);
	}

	public void copyBlocks(int slotNumber) {
		Box rectangle = getRectInBlocks();
		SavedMapBlock captured = SavedMapBlock.fromMap(rectangle, gameMap);
		blockSlots[slotNumber] = captured;
		sayf("Copied %s blocks to slot %s", captured.size(), slotNumber);
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
		return loadBlockSet().compressBlock(currentBlock);
	}

	private void setCurrentBlock(int currentBlock) {
		this.currentBlock = currentBlock;
		paletteTimer = 100;
		sayf("block=%s", currentBlock);
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
				Box fb = alien.freezeBounds;
				if (fb != null) {
					Box s = fb.sub2(getScreenPosition());
					mgc.fillRectangle(s.left, s.top, s.width(), s.height(), 0x80ff0000);
				}

				if (alienTracker.perhapsFreeze(alien, screenBox)) {
					alienIterator.remove();
					// System.out.println("Froze!!");
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
		return ow.loadBlockSet(new BlockSet.Config(levelInfo.worldName, testFlag(FLAG_SEE_MASKS),
				testFlag(FLAG_SEE_HIDDEN)));
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

	// TODO: that wiggly bug with block shuffling
	// it's coz of undrawn stop blocks! (draw them?)

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
				if (!blockEdit.isChangeAt(s) && fillable.test(gameMap.safeGetBlock(s))) {
					blockEdit.setBlock(s, getCurrentBlock());
					nextPositions.add(s.copyAndAdd(1, 0));
					nextPositions.add(s.copyAndAdd(-1, 0));
					nextPositions.add(s.copyAndAdd(0, 1));
					nextPositions.add(s.copyAndAdd(0, -1));
				}
			}
			positions = nextPositions;
		}

		sayf("%s blocks filled", blockEdit.size());
		endBlockEdit();
	}

	public void run() {
		try {
			where(false);
			for (;;) {
				drawFrame();
			}
		}
		catch (ExitException ex) {
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

	// problem:
	// bring something from the Fridge
	// then it is onScreen (you see it's properties) but still frozen (it
	// doesn't draw)
}
