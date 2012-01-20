package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.HashSet;
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
 *   [Alt+E] Enliven this level
 *           (i.e. breath life into LegacyAliens that have since been implemented)
 *           This isn't undoable.
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
 *   [NUMPAD+/-] jump to the next/previous occurrence of the current block
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
 * 
 *   hold [RMB] for full screen block chooser:
 *     [LMB] to pick.
 *     [CURSOR KEYS], [CTRL+M] and [CTRL+I] work in here too
 * 
 * [P] Player simulation mode:
 *   [LMB] move the player towards the mouse
 *   [RMB] jump the player to the mouse
 * 
 * [S] Specification mode:
 *   Level properties are displayed (e.g. level title e.g. horizon number)
 *   and they can be set in the same way as the properties of aliens during
 *   Alien mode.
 * 
 * Always:
 * hold [SPACE] to pan around with the [LMB] (hold [SHIFT] to go faster)
 * [NUMPAD5] jump to the middle of the level
 *           (and the eight numbered keys around it work as expected)
 * [Ctrl+NUMPAD8,2,4,6]     grow the level by one block
 *                          (8=north 2=south 4=west 6=east)
 * [Ctrl+Alt+NUMPAD8,2,4,6] shrink the level by one block
 * [W] where am I?
 * [Ctrl+Z] endless undo
 * [Ctrl+Y] endless redo
 * [ESCAPE] reset
 *          (removes temporary floating palettes and other statefulness)
 * [Alt+T] small test
 *         test the level from the mouse position without the intro
 *         (causes an autosave before launching)
 * [Alt+Shift+T] big test
 *               test the whole level as the player would experience it
 *               (causes an autosave before launching)
 * [Alt+S] save the level
 * [Alt+N] next level
 * [Alt+P] previous level
 * 
 * Notes:
 * The editor doesn't move the mouse pointer while it is in the level-screen.
 * This means "jump" operations above just place the jumped-to-location under
 * the mouse pointer. If you are making heavy use of jumping you'll get less
 * dizzy if you place the mouse pointer in the middle of the screen.
 * </pre>
 */
public class Mapper implements ButtonPressServices {

	// ---------------------------------------------------------------------------
	// CONTROLS

	// commands:

	private static final int ACTION_ENLIVEN = Locks.LOCK_MENU + Keyboard.KEY_E;

	private static final int ACTION_MODE_SPECIFICATION = Keyboard.KEY_S;

	private static final int ACTION_MODE_DRAWING = Keyboard.KEY_D;

	private static final int ACTION_MODE_ALIEN = Keyboard.KEY_A;

	private static final int ACTION_MODE_SIMULATION = Keyboard.KEY_P;

	private static final int ACTION_SMALL_TEST = Keyboard.KEY_T;

	private static final int ACTION_BIG_TEST = Locks.LOCK_SHIFT + ACTION_SMALL_TEST;

	private static final int MACTION_PLAY = Keyboard.KEY_P;

	private static final int MACTION_QUIT = Keyboard.KEY_Q;

	private static final int MACTION_REVERT = Keyboard.KEY_R;

	private static final int MACTION_NEXT_LEVEL = Keyboard.KEY_N;

	private static final int MACTION_PREV_LEVEL = Keyboard.KEY_P;

	private static final int ACTION_REDO = Locks.LOCK_CONTROL + Keyboard.KEY_Y;

	private static final int ACTION_UNDO = Locks.LOCK_CONTROL + Keyboard.KEY_Z;

	private static final int ACTION_TOGGLE_GRID = Locks.LOCK_CONTROL + Keyboard.KEY_G;

	private static final int ACTION_TOGGLE_HIDDEN = Locks.LOCK_CONTROL + Keyboard.KEY_H;

	private static final int ACTION_TOGGLE_MASKS = Locks.LOCK_CONTROL + Keyboard.KEY_M;

	private static final int ACTION_SHRINK_DOWN = Locks.LOCK_CONTROL + Locks.LOCK_MENU + Keyboard.KEY_NUMPAD2;

	private static final int ACTION_SHRINK_UP = Locks.LOCK_CONTROL + Locks.LOCK_MENU + Keyboard.KEY_NUMPAD8;

	private static final int ACTION_SHRINK_RIGHT = Locks.LOCK_CONTROL + Locks.LOCK_MENU + Keyboard.KEY_NUMPAD6;

	private static final int ACTION_SHRINK_LEFT = Locks.LOCK_CONTROL + Locks.LOCK_MENU + Keyboard.KEY_NUMPAD4;

	private static final int ACTION_GROW_LEFT = Locks.LOCK_CONTROL + Keyboard.KEY_NUMPAD4;

	private static final int ACTION_GROW_RIGHT = Locks.LOCK_CONTROL + Keyboard.KEY_NUMPAD6;

	private static final int ACTION_GROW_UP = Locks.LOCK_CONTROL + Keyboard.KEY_NUMPAD8;

	private static final int ACTION_GROW_DOWN = Locks.LOCK_CONTROL + Keyboard.KEY_NUMPAD2;

	private static final int ACTION_NEXT_ALIEN_TYPE = Keyboard.KEY_NEXT;

	private static final int ACTION_PREVIOUS_ALIEN_TYPE = Keyboard.KEY_PRIOR;

	private static final int ACTION_SELECT_ALL = Locks.LOCK_CONTROL + Keyboard.KEY_A;

	private static final int ACTION_UNSELECT = Keyboard.KEY_ESCAPE;

	// things that somehow involve the mouse position:

	// -- things that set the screen position

	private static final int KEY_SEARCH_BACKWARD = Keyboard.KEY_SUBTRACT;

	private static final int KEY_SEARCH_FORWARD = Keyboard.KEY_ADD;

	private static final int ACTION_GO_SE = Keyboard.KEY_NUMPAD3;

	private static final int ACTION_GO_S = Keyboard.KEY_NUMPAD2;

	private static final int ACTION_GO_SW = Keyboard.KEY_NUMPAD1;

	private static final int ACTION_GO_E = Keyboard.KEY_NUMPAD6;

	private static final int ACTION_GO_C = Keyboard.KEY_NUMPAD5;

	private static final int ACTION_GO_W = Keyboard.KEY_NUMPAD4;

	private static final int ACTION_GO_NE = Keyboard.KEY_NUMPAD9;

	private static final int ACTION_GO_N = Keyboard.KEY_NUMPAD8;

	private static final int ACTION_GO_NW = Keyboard.KEY_NUMPAD7;

	// -- things that could become a mode:

	private static final int KEY_PANNING = Keyboard.KEY_SPACE;

	private static final int KEY_EYE_DROPPER = Keyboard.KEY_I;

	private static final int KEY_BLOCK_FILL = Keyboard.KEY_F; // 2!

	private static final int KEY_BLOCK_DELETE = Keyboard.KEY_DELETE;

	private static final int KEY_SET_MARKER = Keyboard.KEY_M;

	private static final int KEY_CREATE_ALIEN = Keyboard.KEY_N;

	private static final int KEY_ALIEN_DUPLICATE = Keyboard.KEY_C;

	private static final int KEY_SELECT_ALIEN = Pointer.KEY_MIDDLE;

	private static final int KEY_WHERE = Keyboard.KEY_W;

	// -- things that must forever remain a keypress:
	private static final int KEY_MOD_BLOCK_CHASE = Keyboard.KEY_C;

	private static final int KEY_CHANGE_TYPE = Pointer.KEY_RIGHT;

	private static final int ALIENS_LOCK = Locks.LOCK_CONTROL;

	private static final int SLOT_COUNT = 12;

	private final static int PASTE_BUFFER_START = Keyboard.KEY_F1;
	private final static int PASTE_BUFFER_END = PASTE_BUFFER_START + SLOT_COUNT - 1;

	// ---------------------------------------------------------------------------

	static public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

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

	private final static int COL_BACKGROUND = 0xff0080ff;

	//
	// stuff to do with the currentBlock
	//
	private int currentBlock;
	private int paletteTimer;

	private final MapperGC mgc;
	private final SimpleMouse mouse;
	private GameMap gameMap;

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

	private MapperMousePosition mmp;

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

	private SlowBoolean squashNext = new SlowBoolean();

	private Box constraints;

	private PlayerPosition sim;

	private KeyEvent keypress;

	private boolean penFullScreen;

	private SelectionScreen blockSelectionScreen;

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

	public Mapper(OuterWorld ow, Coord screenStart) {
		this.ow = ow;
		ColorCycler colorCycler = new ColorCycler();
		mgc = new MapperGC(ow.gc, ow.fonts.debugFont, colorCycler);

		scr = new ScreenPosition(mgc.screenWidth(), mgc.screenHeight(), new Coord(50, 50));

		keyboard = new LocksKeyAdaptor(new TeeKeyAdaptor(ow.mouse, ow.keyboard));
		mouse = new SimpleMouse(ow.mouse);
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

		GameMap g = pl.getMap();
		setGameMap(g);

		loadBlockSet().compressMap(gameMap);

		AlienFactory af = new AlienFactory(alienInfoMap);
		List<Alien> aliens = pl.getAliens(af);

		// player start position
		if (screenStart != null) {
			scr.position(screenStart);
		}
		else {
			PlayerAlien pa = ListUtil.findOne(PlayerAlien.class, aliens);
			if (pa != null) scr.snapTo(pa.c);
		}

		// load the aliens
		for (Alien alien : aliens) {
			alien.connect(animsPool);
			load(alien);
		}

		// build the AlienPalette
		List<AlienInfo> ais = alienInfoMap.getExternal();
		alienPalette = new AlienPalette(ais, mgc, mouse, animsPool);

		createBlockSelectionScreen();
	}

	public void createBlockSelectionScreen() {
		BlockSet bs = loadBlockSet();
		ArrayList<Selectable> content = new ArrayList<Selectable>();
		for (int b = 0; b < bs.getBlockCount(); b++) {
			final int fb = b;
			int x = b % bs.widthInBlocks();
			int y = b / bs.widthInBlocks();
			final Box box = Box.fromTopLeftAndSize(x, y, 1, 1);
			box.mult(Const.BLOCK_SIZE);
			content.add(new Selectable() {

				@Override
				public Box getBounds() {
					return box;
				}

				@Override
				public void draw(MapperGC mgc, Coord where) {
					loadBlockSet().draw(fb, where.x, where.y);
				}
			});
		}
		blockSelectionScreen = new SelectionScreen(mgc, mouse, content);
	}

	public void setGameMap(GameMap g) {
		gameMap = g;
		constraints = gameMap.boundsInPixels();
		Box mapBoundsInPixels = gameMap.boundsInPixels();
		mmp = new MapperMousePosition(mapBoundsInPixels);
		readMouse();

		Box scrollBounds = mapBoundsInPixels.copy();
		int w = mgc.screenWidth() - 1;
		int h = mgc.screenHeight() - 1;
		scrollBounds.left -= w;
		scrollBounds.top -= h;
		scrollBounds.right += w;
		scrollBounds.bottom += h;
		scr.setMapBoundsInPixels(scrollBounds, mapBoundsInPixels);
	}

	void createAlienWithUndoRedo(final Alien alien) {
		validateAlien(alien);
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

		readMouse();

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
		keypress = e == null ? new KeyEvent(0, '\0') : e;
		int k = keypress.keyCode;

		if (mode == Mode.DRAW && keyboard.isDown(KEY_MOD_BLOCK_CHASE)) {
			Coord c = mmp.worldBlocksDelta();
			changeCurrentBlock(c.x, c.y);
		}

		if (pen != null) {
			pen.run();
			if (penFullScreen) {
				showPalettes = false;
			}
			else {
				drawLevel();
			}
		}
		else if (keyboard.isDown(KEY_PANNING)) {
			if (keyboard.isDown(Pointer.KEY_LEFT)) {
				scroll(mmp.pixelsDelta());
			}
			drawLevel();
		}
		else if (mode == Mode.DRAW && k == KEY_CHANGE_TYPE) {
			blockSelectionScreen.begin();
			startPen(k, new Pen() {
				@Override
				boolean fullScreen() {
					return true;
				}

				@Override
				void stroke() {
					flagSelectionKeys();
					blockSelectionScreen.draw();
				}

				@Override
				void up() {
					int b = blockSelectionScreen.getHover();
					if (b >= 0) {
						currentBlock = b;
					}
					blockSelectionScreen.end();
				}
			});
		}
		else if (mode == Mode.ALIEN && k == KEY_CHANGE_TYPE) {
			alienPalette.begin();
			startPen(k, new Pen() {
				@Override
				boolean fullScreen() {
					return true;
				}

				@Override
				void stroke() {
					char c = keypress.keyChar;
					alienPalette.jumpTo(c);

					int k = keypress.keyCode;
					if (k == Pointer.KEY_UP || k == ACTION_PREVIOUS_ALIEN_TYPE) {
						alienPalette.moveBy(-1);
					}
					if (k == Pointer.KEY_DOWN || k == ACTION_NEXT_ALIEN_TYPE) {
						alienPalette.moveBy(1);
					}
					alienPalette.draw();
				}

				@Override
				void up() {
					// int b = blockSelectionScreen.getHover();
					// if (b >= 0) {
					// currentBlock = b;
					// }
					alienPalette.end();
				}
			});
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
				sayf("Moved to " + nc);
			}
			if (k == KEY_WHERE) {
				where(true);
			}

			if (k == ACTION_UNDO) {
				if (!undoControler.undo()) say("Nothing more to undo");
			}
			if (k == ACTION_REDO) {
				if (!undoControler.redo()) say("Nothing more to redo");
			}
			if (k == ACTION_UNSELECT) {
				marker = null;
			}
			drawLevel();
		}

		if (showPalettes) {
			drawOverlays();
		}
		mgc.endDrawing();

		if (pen == null) {
			if (k == Locks.LOCK_MENU + ACTION_SMALL_TEST) {
				testLevel(false);
			}
			if (k == Locks.LOCK_MENU + ACTION_BIG_TEST) {
				testLevel(true);
			}
			if (k == Locks.LOCK_MENU + ACTION_MODE_SPECIFICATION) {
				int playerCount = ListUtil.count(PlayerAlien.class, getAliensReadOnly());
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
				int justKey = k & (~Locks.LOCK_ALL);
				int sureLocks = Locks.LOCK_CONTROL | Locks.LOCK_SHIFT;
				boolean sure = (k & sureLocks) == sureLocks;

				if (justKey == MACTION_QUIT && mustBeSure(sure, "Quit")) {
					throw new OuterWorld.ExitException();
				}
				if (justKey == MACTION_REVERT && mustBeSure(sure, "Revert")) {
					if (undoControler.changes() != 0) {
						throw new ExitException();
					}
				}
				if (justKey == MACTION_PLAY && mustBeSure(sure, "Play")) {
					ow.resetStats();
					ow.launchGame();
					throw new ExitException();
				}
				if (justKey == MACTION_NEXT_LEVEL && !ow.lastLevel() && mustBeSure(sure, "Next level")) {
					ow.levelNumber++;
					throw new ExitException();
				}
				if (justKey == MACTION_PREV_LEVEL && !ow.firstLevel() && mustBeSure(sure, "Previous level")) {
					ow.levelNumber--;
					throw new ExitException();
				}
			}

			growAndShrinkMap(k);
		}
	}

	public void growAndShrinkMap(int k) {
		if (k == ACTION_GROW_LEFT) changeMapBounds(1, 0, 0, 0);
		if (k == ACTION_GROW_RIGHT) changeMapBounds(0, 1, 0, 0);
		if (k == ACTION_GROW_UP) changeMapBounds(0, 0, 1, 0);
		if (k == ACTION_GROW_DOWN) changeMapBounds(0, 0, 0, 1);
		if (k == ACTION_SHRINK_LEFT) changeMapBounds(-1, 0, 0, 0);
		if (k == ACTION_SHRINK_RIGHT) changeMapBounds(0, -1, 0, 0);
		if (k == ACTION_SHRINK_UP) changeMapBounds(0, 0, -1, 0);
		if (k == ACTION_SHRINK_DOWN) changeMapBounds(0, 0, 0, -1);
	}

	public void readMouse() {
		Coord m = mouse.get();
		mmp.update(m, getScreenPosition().add2(m));
	}

	public void enliven() {
		// enliven
		List<Alien> all = getAliens();
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
			if (mode == Mode.DRAW) {
				changeCurrentBlock(0, 0);
			}
		}
		say(s);
	}

	public int countAliens(Class<? extends Alien> t) {
		return ListUtil.count(t, getAliensReadOnly());
	}

	private boolean mustBeSure(boolean sure, String task) {
		if (sure || undoControler.changes() == 0) return true;
		sayf("%s: Abandon %s unsaved changes? Add Ctrl+Shift if certain", task, undoControler.changes());
		return false;
	}

	public void drawOverlays() {
		if (mode == Mode.ALIEN) drawProps();
		if (mode == Mode.SPECIFICATION) {
			drawProps();
		}
		if (mode == Mode.PLAYERSIMULATION) {
			if (sim.ceiling != null) {
				Coord d = sim.ceiling.sub2(getScreenPosition());
				mgc.drawSight(d.x, d.y, 40, 0xffffffff);
			}

			Coord c = sim.get().sub2(getScreenPosition());
			mgc.drawSight(c.x, c.y, 10, sim.isStanding() ? 0xff00ff00 : 0xffff0000);
		}
		drawPalettes();

		if (messTimer != 0) {
			messTimer--;
			bottomUpStatusLayer.draw(0, 0, messText);
		}
	}

	public void saveMap(boolean autoSave) {
		String levelText = PersistedLevel.staticSave(levelInfo, gameMap, getAliensReadOnly());
		TTResource.saveMap(levelInfo.filename, levelText, autoSave);
	}

	private Coord convertNumCoord(Coord nc) {
		Box p = gameMap.boundsInPixels();
		int x = p.left + Math2.fracMult(nc.x, p.width() - 1, 2);
		int y = p.top + Math2.fracMult(nc.y, p.height() - 1, 2);
		return new Coord(x, y);
	}

	private void testLevel(boolean bigTest) {
		saveMap(true);

		ow.resetStats();

		World w = new World(ow);
		if (!bigTest) {
			w.configurePerformIntro(false);
			w.configurePlayerStart(mmp.worldPixels());
			// w.configureScriptRecording(levelInfo.filename);
			w.configureSeeHidden(testFlag(FLAG_SEE_HIDDEN));
			w.configureSeeMasks(testFlag(FLAG_SEE_MASKS));
		}
		w.configureMapText(PersistedLevel.staticSave(levelInfo, gameMap, getAliensReadOnly()));
		w.testLevelFromMapper();
		setScreenPosition(w.getScreenPosition());

		System.out.println("DONE TESTING");
	}

	private Coord numCoord(int k) {
		if (k == ACTION_GO_NW) return new Coord(0, 0);
		if (k == ACTION_GO_N) return new Coord(1, 0);
		if (k == ACTION_GO_NE) return new Coord(2, 0);
		if (k == ACTION_GO_W) return new Coord(0, 1);
		if (k == ACTION_GO_C) return new Coord(1, 1);
		if (k == ACTION_GO_E) return new Coord(2, 1);
		if (k == ACTION_GO_SW) return new Coord(0, 2);
		if (k == ACTION_GO_S) return new Coord(1, 2);
		if (k == ACTION_GO_SE) return new Coord(2, 2);
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
		if (k == KEY_EYE_DROPPER) {
			setCurrentBlock(gameMap.getBlock(mmp.worldBlocks()));
		}
		if (k == KEY_SET_MARKER) {
			marker = marker == null ? mmp.worldBlocks() : null;
		}
		if (k == ACTION_SELECT_ALL) {
			marker = new Coord(0, 0);
			moveMouse(convertNumCoord(new Coord(2, 2)));
		}
		if (k == KEY_BLOCK_FILL) {
			if (marker == null) {
				floodFill(gameMap.getBlock(mmp.worldBlocks()));
			}
			else {
				fillRect(getCompressedCurrentBlock());
			}
		}

		if (k == KEY_SEARCH_FORWARD) findBlock(1);
		if (k == KEY_SEARCH_BACKWARD) findBlock(-1);
		if (k == KEY_BLOCK_DELETE) fillRect(0);
		if (k == ALIENS_LOCK + KEY_BLOCK_DELETE && marker != null) {
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

		if (k == Locks.LOCK_ALL + KEY_MOD_BLOCK_CHASE) {
			loadBlockSet().legacyCapture(gameMap);
		}
	}

	public void changeMode(int k) {
		if (changeMode(k, ACTION_MODE_ALIEN, Mode.ALIEN, "Alien Mode")) {
			generateButtons(selectedAlien);
		}
		changeMode(k, ACTION_MODE_DRAWING, Mode.DRAW, "Drawing Mode");
		if (changeMode(k, ACTION_MODE_SPECIFICATION, Mode.SPECIFICATION, "Specification Mode")) {
			generateButtons(levelInfo);
		}
		if (changeMode(k, ACTION_MODE_SIMULATION, Mode.PLAYERSIMULATION, "Player Simulation Mode")) {
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

	private void findBlock(int dir) {
		int s = gameMap.area();
		Coord c = mmp.worldBlocks();
		int p = gameMap.ungenerate(c);

		for (int i = 1; i < s; i++) {
			int z = (p + i * dir + s) % s;
			Coord q = gameMap.generate(z);
			System.out.println(String.format("%s test %s", c, q));
			if (gameMap.getBlock(q) == currentBlock) {
				sayf("Block found");
				q.mul(Const.BLOCK_SIZE);
				q.add(new Coord(Const.BLOCK_SIZE / 2, Const.BLOCK_SIZE / 2));
				moveMouse(q);
				return;
			}
		}
		sayf("Block not found");

	}

	private void findType(int dir) {
		ArrayList<Alien> candidates = new ArrayList<Alien>();
		AlienInfo t = alienPalette.get();
		for (Alien a : getAliensReadOnly()) {
			if (a.alienInfo == t) {
				candidates.add(a);
			}
		}
		if (candidates.size() > 0) {
			// sort the candidates by their position
			ListUtil.sort(candidates, new SortKeyGenerator<Alien, Coord>() {
				@Override
				public Coord gen(Alien t) {
					return t.getLocation();
				}
			});
			int z = candidates.indexOf(getSelectedAlien());
			// did we find the current one?
			if (z < 0) {
				// no: so we'll start at the first one
				z = 0;
			}
			else {
				// yes: go forward or back as requested (wrapping around)
				z += candidates.size() + dir;
				z %= candidates.size();
			}
			// jump to that alien
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
		flagSelectionKeys();

		if (keyboard.isDown(Pointer.KEY_LEFT)) {
			for (int x = 0; x < 5; x++) {
				Coord d = mmp.worldPixels();
				Coord s = sim.get();
				Coord diff = d.sub2(s);
				diff.signum();
				simDiff(diff);
			}
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

		if (k == KEY_SELECT_ALIEN) {
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

					public Coord getBounds() {
						return mmp.worldPixels().sub2(batGrip);
					}

					private Coord whereSnapped() {
						boolean isDown = keyboard.isDown(Locks.LOCK_SHIFT);
						if (isDown) {
							if (origin == null) origin = getBounds();
						}
						else {
							origin = null;
						}
						return computeSnap(getBounds(), origin, 8);
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
			if (k == KEY_BLOCK_DELETE) deleteSelectedAlien();
			if (k == KEY_ALIEN_DUPLICATE) copySelectedAlien();
		}
		if (k == KEY_SEARCH_FORWARD) findType(1);
		if (k == KEY_SEARCH_BACKWARD) findType(-1);
		if (k == KEY_CREATE_ALIEN) createAlien();
		flagSelectionKeys();

		if (k == ACTION_ENLIVEN) enliven();

		if (k == KEY_EYE_DROPPER && haveAlien()) {
			alienPalette.find(getSelectedAlien().alienInfo);
		}
		if (k == ACTION_PREVIOUS_ALIEN_TYPE) {
			changeAlien(-1);
		}
		if (k == ACTION_NEXT_ALIEN_TYPE) {
			changeAlien(1);
		}
	}

	private void changeAlien(int i) {
		alienPalette.moveBy(i);
		sayf("alien=%s", alienPalette.get().name); // SAYIT
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
		penFullScreen = p.fullScreen();
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
			// if (mode == Mode.ALIEN) alienPalette.showAlienPalette();
			if (mode == Mode.DRAW) BlockPalette.showSmallPalette(mgc, loadBlockSet(), getCurrentBlock());
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
		drawAliens();
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

	public void showAlienPalette() {
		paletteTimer = 100;
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
		if (k == Keyboard.KEY_UP) changeCurrentBlock(0, -1);
		if (k == Keyboard.KEY_DOWN) changeCurrentBlock(0, 1);
		if (k == Keyboard.KEY_LEFT) changeCurrentBlock(-1, 0);
		if (k == Keyboard.KEY_RIGHT) changeCurrentBlock(1, 0);
		flagSelectionKeys();
	}

	public void flagSelectionKeys() {
		int k = keypress.keyCode;
		if (k == ACTION_TOGGLE_MASKS) flipFlag(FLAG_SEE_MASKS);
		if (k == ACTION_TOGGLE_HIDDEN) flipFlag(FLAG_SEE_HIDDEN);
		if (k == ACTION_TOGGLE_GRID) flipFlag(FLAG_SEE_GRID);
	}

	private void flipFlag(int flip) {
		flags ^= flip;
		sayf("Masks: %s | Hidden Blocks: %s | Grid: %s", testFlagAsString(FLAG_SEE_MASKS),
				testFlagAsString(FLAG_SEE_HIDDEN), testFlagAsString(FLAG_SEE_GRID));
	}

	private String testFlagAsString(int test) {
		return testFlag(test) ? "ON " : "OFF";
	}

	private void changeCurrentBlock(int dx, int dy) {
		BlockSet bs = loadBlockSet();
		int delta = dy * bs.widthInBlocks() + dx;
		int blockCount = bs.getBlockCount();
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

	private void deleteAlien(Alien alien) {
		getAliens().remove(alien);
		setSelectedAlien(null);
	}

	private List<Alien> getAliens() {
		return alienTracker.get();
	}

	private Iterable<Alien> getAliensReadOnly() {
		return alienTracker;
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

	private HasProps getSelectedObject() {
		if (mode == Mode.ALIEN) return getSelectedAlien();
		if (mode == Mode.SPECIFICATION) return levelInfo;
		assert false;
		return null;
	}

	private void startObjectEdit() {
		startObjectEdit(getSelectedObject());
	}

	public void startObjectEdit(HasProps a) {
		assert alienEdit == null;
		alienEdit = new ObjectEdit(a);
	}

	private void endObjectEdit() {
		assert alienEdit != null;
		HasProps a = alienEdit.beingEditted();
		validateAlien(a);
		alienEdit.removeMatching();
		alienEdit.swap();
		undoControler.redoThenAdd(alienEdit);
		alienEdit = null;

		squashNext.set(true);
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
			Coord bottomRight = c.copyAndAdd(slot.w - 1, slot.h - 1);
			if (gameMap.boundsInBlocks().inside(bottomRight)) {
				// paste it!
				MapEdit edit = MapEdit.create(gameMap, c, slot.copy());
				submitMapEdit(edit);
				sayf("Pasted %s blocks from slot %s", slot.size(), slotNumber);
			}
			else {
				say("Does not fit!");
				// int xs = c.x + slot.w - gameMap.width();
				// int ys = c.y + slot.h - gameMap.height();
				// if (xs > 0) {
				// sayf("Move left by at least %s blocks", xs);
				// }
				// else if (ys > 0) {
				// sayf("Move up by at least %s blocks", ys);
				// }

			}
		}
	}

	public void copyAliens(int slotNumber) {
		Box rectangle = getRectInBlocks();
		rectangle.mult(Const.BLOCK_SIZE);
		List<Alien> captured = new ArrayList<Alien>();
		for (Alien a : getAliensReadOnly()) {
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
		sayf("block=%s", getCompressedCurrentBlock()); // SAYIT

		blockSelectionScreen.setHover(currentBlock);
	}

	// ---------------------------------------------------------------------------

	public Coord getScreenPosition() {
		return scr.position();
	}

	public void setScreenPosition(Coord c) {
		Coord s = scr.position().copy();
		scr.position(c);
		System.out.println(String.format("before %s set %s after %s", s, c, scr.position()));
		readMouse();
	}

	private void drawAliens() {
		List<Alien> a = squashNext.set(false) ? alienTracker.get() : alienTracker.startDrawing(scr.box());
		updateList(a, Alien.DEPTH_BG_SCENARY);
		updateList(a, Alien.DEPTH_LIFTS);
		updateList(a, Alien.DEPTH_COLLECTABLES);
		updateList(a, Alien.DEPTH_ALIENS);
		updateList(a, Alien.DEPTH_FG_SCENARY);
		alienTracker.endDrawing(scr.box());
	}

	private void updateList(List<Alien> alienList, int depth) {
		for (Iterator<Alien> alienIterator = alienList.iterator(); alienIterator.hasNext();) {
			Alien alien = alienIterator.next();
			if (alien.depth == depth) {
				alien.freezeBounds = null;
				alien.mapperUpdate();
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
		for (Alien a : getAliensReadOnly()) {
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

	private boolean inTheGround(Coord c) {
		// outside of the map it is ground
		// (stops things falling outside of the map!)
		if (gameMap.boundsInBlocks().inside(c)) return true;
		int block = gameMap.getBlock(c.asr2(Const.BLOCK_SHIFT));
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

	static class SavedMapBlockWithPosition {
		final private Coord c;
		final private SavedMapBlock s;

		SavedMapBlockWithPosition(Box from, GameMap gameMap) {
			c = from.topLeft();
			s = SavedMapBlock.fromMap(from, gameMap);
		}

		void restore(GameMap gameMap) {
			s.write(c, gameMap);
		}
	}

	public void changeMapBounds(int l, int r, int t, int b) {
		final Box oBounds = gameMap.boundsInBlocks().copy();
		final Box nBounds = oBounds.copy();
		nBounds.left -= l;
		nBounds.right += r;
		nBounds.top -= t;
		nBounds.bottom += b;

		if (nBounds.area() == 0) {
			say("Map cannot be shrunk out of existence!");
			return;
		}

		undoControler.mark();

		// capture anything strips of blocks that we are loosing from the edge
		Box cap = null;
		if (l < 0) {
			cap = Box.fromTopLeftAndSize(oBounds.topLeft(), 1, oBounds.height());
		}
		if (r < 0) {
			cap = Box.fromTopLeftAndSize(oBounds.topRight(), 1, oBounds.height());
		}
		if (t < 0) {
			cap = Box.fromTopLeftAndSize(oBounds.topLeft(), oBounds.width(), 1);
		}
		if (b < 0) {
			cap = Box.fromTopLeftAndSize(oBounds.bottomLeft(), oBounds.width(), 1);
		}
		final SavedMapBlockWithPosition capture = cap == null ? null : new SavedMapBlockWithPosition(cap, gameMap);

		// now here is we change the map:
		undoControler.redoThenAdd(new UndoRedo() {
			@Override
			public boolean redo() {
				changeMapBounds(nBounds);
				return true;
			}

			@Override
			public void undo() {
				changeMapBounds(oBounds);
				if (capture != null) {
					capture.restore(gameMap);
				}
			}
		});

		for (Alien a : getAliens()) {
			startObjectEdit(a);
			validateAlien(a);
			endObjectEdit();
		}

		// merge anything we've done into a single undo/redo event
		undoControler.fold();
	}

	public void changeMapBounds(Box nBounds) {
		GameMap sourceMap = gameMap;
		GameMap destinationMap = new GameMap(nBounds, gameMap);
		setGameMap(destinationMap);
		sayf("Map changed from %s to %s", sourceMap.boundsInBlocks(), destinationMap.boundsInBlocks());
	}

	// TODO: that wiggly bug with block shuffling
	// it's coz of undrawn stop blocks! (draw them?)

	private void floodFill(int fillable) {
		startBlockEdit();

		// naive implementation but at least it is breadth first
		// so doesn't keep too many false leads
		HashSet<Coord> positions = new HashSet<Coord>();
		positions.add(mmp.worldBlocks());

		while (!positions.isEmpty()) {
			HashSet<Coord> nextPositions = new HashSet<Coord>();
			for (Coord s : positions) {
				if (!blockEdit.isChangeAt(s) && gameMap.safeGetBlock(s) == fillable) {
					blockEdit.setBlock(s, getCompressedCurrentBlock());
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
		List<Alien> as = getAliens();
		for (Iterator<Alien> iterator = as.iterator(); iterator.hasNext();) {
			Alien alien = iterator.next();
			if (ap.is(alien)) {
				iterator.remove();
				lost.add(alien);
			}
		}
		return lost;
	}

	// problem:
	// bring something from the Fridge
	// then it is onScreen (you see it's properties) but still frozen (it
	// doesn't draw)
}
