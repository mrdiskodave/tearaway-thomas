package com.nney.tt.flow;

import com.nney.coroutines.Coroutine;
import com.nney.tt.Launcher;
import com.nney.tt.OuterWorld;
import com.nney.tt.PersistedLevel;
import com.nney.tt.World;
import com.nney.tt.World.Outcome;
import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.KeyEvent;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.RecordedJoystick;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.OpenableTools;

/**
 * The game from switch-on, as the original's main and play_game in s195: the
 * intro demo with the title pages over it, then one world's demo, then the intro
 * again and the next world, round and round until someone presses fire. Then a
 * game, and back to the demos. A new high score's name is entered over the
 * next intro demo, before its title pages.
 *
 * It's written as plain straight-line code rather than a state machine. That
 * works because whoever is running draws the frames: {@link World} has its own
 * frame loops (and does everything that happens around a level: fades, the
 * circle, the messages) and each frame is shown when
 * {@link GraphicsContext#endDrawing()} is called.
 *
 * The title pages run over a demo, so there the demo is the main loop and the
 * pages are a {@link Coroutine} that it steps once a frame, just as the
 * original's DSstart task was stepped by its main loop.
 */
public final class GameFlow implements Launcher {
	/** The original cut the intro recording off here (st $526(a0)). */
	private static final int INTRO_DEMO_FRAMES = 1318;

	/** The world demos, from demlevs, dltimes and scriptnames in s195. */
	private static final Object[][] DEMOS = { //
			// level (from 1), frames, recording
			{ 8, 16 * 50, "wood" }, //
			{ 12, 10 * 50, "toy" }, //
			{ 27, 21 * 50 - 25, "ghost" }, //
			{ 34, 30 * 50, "ice" }, //
			{ 47, 17 * 50, "future" }, //
	};

	private static final String PRESS_TO_PLAY = "press jump to play";

	private final int startLevel;

	private OuterWorld ow;
	private GraphicsContext gc;
	private Font font;
	private Joystick joystick;
	private Keyboard keyboard;
	private HighScores highScores;

	/** The demo being played. */
	private World demoWorld;

	/** A high score waiting for its name (entered over the next intro demo). */
	private HighScores.Entry newHighScore;

	/** While a name is entered, fire picks letters rather than starting a game. */
	private boolean enteringName;

	/** Frames since switch-on, for the colour cycling. */
	private int cycleClock;

	/**
	 * @param startLevel
	 *            -1 to begin with the title sequence as usual, or a level
	 *            number (from 0) to go straight into a game there.
	 */
	public GameFlow(int startLevel) {
		this.startLevel = startLevel;
	}

	@Override
	public void launch(OuterWorld outerWorld) {
		ow = outerWorld;
		gc = ow.gc;
		font = ow.fonts.font;
		joystick = ow.joystick;
		keyboard = ow.keyboard;
		if (highScores == null) highScores = new HighScores(HighScores.defaultFile());

		if (startLevel >= 0) {
			if (!playGame(startLevel)) return;
		}
		for (;;) {
			if (!attract()) return;
			if (!playGame(0)) return;
		}
	}

	/** Has someone (the developer's Tab key: the map editor) switched us off? */
	private boolean stillInCharge() {
		return ow.bootstrap == this;
	}

	// ---------------------------------------------------------------------------
	// ATTRACT MODE

	/**
	 * The intro demo with the title pages, then a world's demo, and again with
	 * the next world, until someone presses fire.
	 *
	 * @return <code>false</code> if we've been switched off.
	 */
	private boolean attract() {
		// (reset_demo: after a game it starts again from the first world)
		for (int next = 0;; next = (next + 1) % DEMOS.length) {
			Outcome o = playDemo(0, "intro", INTRO_DEMO_FRAMES, true, Integer.MAX_VALUE, "intro", false,
					new Coroutine("titles", this::titleSequence));
			if (o != Outcome.DEMO_OVER) return o == Outcome.DEMO_INTERRUPTED;

			Object[] d = DEMOS[next];
			o = playDemo((Integer) d[0] - 1, (String) d[2], -1, false, (Integer) d[1], null, true,
					new Coroutine("demo " + d[2], this::worldDemo));
			if (o != Outcome.DEMO_OVER) return o == Outcome.DEMO_INTERRUPTED;
		}
	}

	private Outcome playDemo(int level, String recording, int maxRecordingFrames, boolean loop, final int frames,
			String music, boolean worldLogo, final Coroutine overlay) {
		ow.reset();
		ow.levelNumber = level;
		byte[] rec = OpenableTools.mustLoad(TTResource.demo(recording));
		World w = new World(ow);
		demoWorld = w;
		final int[] frame = new int[1];
		w.configureDemo(new RecordedJoystick(rec, maxRecordingFrames, loop), () -> {
			frame[0]++;
			cycleClock++;
			boolean more = overlay.step();
			return more && frame[0] < frames;
		});
		w.configureDemoMusic(music);
		w.configureWorldLogo(worldLogo);
		// (each demo shows its world's logo afresh)
		ow.worldLogoShown = null;
		w.configureDemoInterruptible(() -> !enteringName);
		try (Coroutine c = overlay; w) {
			Outcome o = w.playLevel();
			System.out.println("FLOW: demo " + recording + " -> " + o);
			return stillInCharge() ? o : Outcome.TO_MAPPER;
		}
		finally {
			demoWorld = null;
			enteringName = false;
			ow.reset();
		}
	}

	/** Nothing is drawn over a world's demo. */
	private void worldDemo(Coroutine co) {
		for (;;) {
			drainKeys();
			co.pause();
		}
	}

	/**
	 * DSstart in s195, run as a coroutine over the intro demo: each
	 * {@link Coroutine#pause()} is one frame. Each page goes up whole, at full
	 * brightness, for the time its text asked for (the 13,n codes: twice n
	 * frames), with the demo carrying on behind it. Then the demo is over.
	 */
	private void titleSequence(Coroutine co) {
		// "exit open" and "hurry up" would be lost under the pages
		demoWorld.setStatusTextsHidden(true);
		if (newHighScore != null) {
			enterName(co, newHighScore);
			newHighScore = null;
		}
		showLogo(co, "0logotitle", 80);
		showText(co, Texts.WRITTEN_BY, 200, true);
		showText(co, Texts.THANKS_1, 140, false);
		showText(co, Texts.THANKS_2, 140, false);
		showText(co, Texts.THANKS_3, 140, false);
		showText(co, Texts.highScores(highScores, null, null), 200, false);
		// clearscreen_text: a moment with nothing, then done_level
		for (int f = 0; f < 4; f++) {
			drainKeys();
			co.pause();
		}
	}

	// ---------------------------------------------------------------------------
	// TITLE PAGES (all run inside a coroutine)

	/** The title logo, still, in the middle of the screen. */
	private void showLogo(Coroutine co, String name, int frames) {
		Sprite logo = loadPicture(name);
		try {
			for (int f = 0; f < frames; f++) {
				drainKeys();
				logo.drawByHandle(gc.screenWidth() / 2, gc.screenHeight() / 2, false);
				co.pause();
			}
		}
		finally {
			logo.close();
		}
	}

	/**
	 * Load a whole picture as a sprite with its handle in the middle. (Unlike
	 * {@link com.nney.tt.sprites.LargeImageFrameLoader} it doesn't need an
	 * odd-sized image.)
	 */
	private Sprite loadPicture(String name) {
		SimpleImage si = new SimpleImage(OpenableTools.mustLoad(TTResource.bareSprite(name)));
		Bounds b = si.bounds();
		return new Sprite(gc, si.view(b), si.width() / 2 - b.left, si.height() / 2 - b.top, false);
	}

	private void showText(Coroutine co, String markup, int frames, boolean invite) {
		ScreenText text = new ScreenText(gc, font, markup);
		try {
			for (int f = 0; f < frames; f++) {
				drainKeys();
				text.draw();
				if (invite) drawPressToPlay();
				co.pause();
			}
		}
		finally {
			text.close();
		}
	}

	/**
	 * "press fire to play" on the "written by" page, in the original's cycling
	 * colour: yellow exclusive-or'd with a grey going up and down a step a
	 * frame (cycle and tpcycle in s195).
	 */
	private void drawPressToPlay() {
		int step = cycleClock % 30;
		int level = step < 15 ? step + 1 : 30 - step; // 1..15..0
		int grey = level * 0x111;
		int c = 0xff0 ^ grey;
		int argb = 0xff000000 | ((c >> 8 & 15) * 0x11) << 16 | ((c >> 4 & 15) * 0x11) << 8 | (c & 15) * 0x11;
		int w = font.computeWidth(0, PRESS_TO_PLAY);
		font.draw((gc.screenWidth() - w) / 2, gc.screenHeight() - 64, argb, 0, PRESS_TO_PLAY);
	}

	private void drainKeys() {
		while (keyboard.nextEvent() != null) {
			// discard
		}
	}

	// ---------------------------------------------------------------------------
	// A GAME

	/**
	 * @return <code>false</code> if we've been switched off.
	 */
	private boolean playGame(int firstLevel) {
		ow.ah.stopMusic();
		ow.reset();
		ow.levelNumber = firstLevel;
		// (blkset_logoed: the first level's world gets its logo too)
		ow.worldLogoShown = null;
		int last = PersistedLevel.levelCount() - 1;
		for (;;) {
			Outcome o;
			try (World world = new World(ow)) {
				if (ow.devPlayerStart != null) {
					world.configurePlayerStart(ow.devPlayerStart);
					ow.devPlayerStart = null;
				}
				if (ow.levelNumber == last) {
					world.configureEnding(() -> Texts.ending(ow.levelsCompleted, ow.gemsCollectedTotal));
				}
				o = world.playLevel();
			}
			System.out.println("FLOW: level " + ow.levelNumber + " -> " + o + " (lives " + ow.lives + ", score "
					+ ow.score + ")");
			if (!stillInCharge()) return false;
			switch (o) {
			case COMPLETED:
				// (World has already moved levelNumber on by one)
				boolean[] secret = { ow.secretBonusFound };
				ow.levelNumber = Progression.next(ow.levelNumber - 1, ow.starCollected, secret,
						Progression.FROM_LEVEL_FILES);
				ow.secretBonusFound = secret[0];
				// after the last level the original goes round again from the first
				if (ow.levelNumber > last) ow.levelNumber = 0;
				break;
			case GAME_OVER:
				newHighScore = highScores.add(ow.score);
				System.out.println("FLOW: game over, score " + ow.score
						+ (newHighScore != null ? " is a high score" : ""));
				return true;
			case LIFE_LOST:
			default:
				// same level again
				break;
			}
		}
	}

	// ---------------------------------------------------------------------------
	// A NEW HIGH SCORE (over the intro demo)

	/** Edge-detects the fire button and stick, one read per frame. */
	private final class Stick {
		private int last = -1; // -1: pretend everything was held, so we need a fresh press
		private int now;

		void read() {
			int j = joystick.get();
			if (last == -1) last = j;
			else last = now;
			now = j;
		}

		boolean pressed(int mask) {
			return (now & mask) != 0 && (last & mask) == 0;
		}

		boolean held(int mask) {
			return (now & mask) != 0;
		}
	}

	/**
	 * HSstart in s195: the table with "enter your name" over the demo, the
	 * name typed (or chosen with the stick: up and down for a letter, fire to
	 * take it, left to go back), then the finished table for 2 seconds.
	 */
	private void enterName(Coroutine co, HighScores.Entry e) {
		final String letters = "abcdefghijklmnopqrstuvwxyz0123456789.-!?";
		enteringName = true;
		StringBuilder typed = new StringBuilder();
		int choice = 0;
		int repeat = 0;
		Stick stick = new Stick();
		ScreenText text = null;
		String shown = null;
		try {
			for (int f = 0;; f++) {
				stick.read();
				boolean done = false;
				KeyEvent k;
				while ((k = keyboard.nextEvent()) != null) {
					char c = Character.toLowerCase(k.keyChar);
					if (k.keyCode == Keyboard.KEY_BACK) {
						if (typed.length() > 0) typed.setLength(typed.length() - 1);
					}
					else if (k.keyCode == Keyboard.KEY_RETURN) {
						done = true;
					}
					else if (c != 0 && letters.indexOf(c) >= 0 && typed.length() < HighScores.INITIALS) {
						typed.append(c);
						choice = letters.indexOf(c);
					}
				}

				int dir = stick.held(Joystick.UP) ? -1 : stick.held(Joystick.DOWN) ? 1 : 0;
				if (dir == 0) repeat = 0;
				else if (repeat-- <= 0) {
					choice = (choice + dir + letters.length()) % letters.length();
					repeat = repeat < -1 ? 4 : 12; // slow at first, then quicker
				}
				if (stick.pressed(Joystick.FIRE)) {
					if (typed.length() < HighScores.INITIALS) typed.append(letters.charAt(choice));
				}
				if (stick.pressed(Joystick.LEFT) && typed.length() > 0) {
					typed.setLength(typed.length() - 1);
				}
				boolean finished = typed.length() == HighScores.INITIALS || (done && typed.length() > 0);
				if (finished) e.initials = typed.toString();

				String cursor = finished ? "" : (f / 8) % 2 == 0 ? String.valueOf(letters.charAt(choice)) : " ";
				String markup = finished ? Texts.highScores(highScores, e, null)
						: Texts.enterInitials(highScores, e, typed + cursor);
				if (!markup.equals(shown)) {
					if (text != null) text.close();
					text = new ScreenText(gc, font, markup);
					shown = markup;
				}
				text.draw();
				co.pause();
				if (finished) break;
			}
			highScores.save();
			// HSdone: the finished table for 100 frames
			for (int f = 0; f < 100; f++) {
				drainKeys();
				text.draw();
				co.pause();
			}
		}
		finally {
			if (text != null) text.close();
			if (e.initials.isEmpty()) e.initials = "???";
			enteringName = false;
		}
	}
}
