package com.nney.tt.flow;

import com.nney.coroutines.Coroutine;
import com.nney.tt.Launcher;
import com.nney.tt.OuterWorld;
import com.nney.tt.PersistedLevel;
import com.nney.tt.World;
import com.nney.tt.World.Outcome;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.KeyEvent;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.RecordedJoystick;
import com.nney.tt.resources.TTResource;
import com.nney.tt.gfx.Bounds;
import com.nney.tt.gfx.SimpleImage;
import com.nney.tt.sprites.Sprite;
import com.nney.utils.OpenableTools;

/**
 * The game from switch-on: title sequence and demos, a game, game over or the
 * ending, high scores, and round again.
 *
 * It's written as plain straight-line code rather than a state machine. That
 * works because whoever is running draws the frames: {@link World} has its own
 * frame loops and so do the little loops in here, and each frame is shown when
 * {@link GraphicsContext#endDrawing()} is called.
 *
 * The one place two things have to advance together is the title sequence,
 * which runs over a demo of level 1. There the demo is the main loop and the
 * titles are a {@link Coroutine} that it steps once a frame, just as the
 * original's DSstart task was stepped by its main loop.
 */
public final class GameFlow implements Launcher {
	/** The original cut the intro recording off here (st $526(a0)). */
	private static final int INTRO_DEMO_FRAMES = 1318;

	/** A music slot World doesn't use. */
	private static final int TITLE_MUSIC_SLOT = 4;

	/** The attract-mode demos, from demlevs, dltimes and scriptnames in s195. */
	private static final Object[][] DEMOS = { //
			// level (from 1), frames, recording, logo
			{ 8, 16 * 50, "wood", "0logow" }, //
			{ 12, 10 * 50, "toy", "0logot" }, //
			{ 27, 21 * 50 - 25, "ghost", "0logog" }, //
			{ 34, 30 * 50, "ice", "0logoi" }, //
			{ 47, 17 * 50, "future", null }, //
	};

	private static final String PRESS_TO_PLAY = "press jump to play";

	private final int startLevel;

	private OuterWorld ow;
	private GraphicsContext gc;
	private Font font;
	private Joystick joystick;
	private Keyboard keyboard;
	private HighScores highScores;

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

	/** Has someone (the developer's Esc key) switched us off? */
	private boolean stillInCharge() {
		return ow.bootstrap == this;
	}

	// ---------------------------------------------------------------------------
	// ATTRACT MODE

	/**
	 * Title sequence over the intro demo, then the demos of each world, round
	 * and round until someone presses fire.
	 *
	 * @return <code>false</code> if we've been switched off.
	 */
	private boolean attract() {
		ow.ah.loadMusic(TITLE_MUSIC_SLOT, "intro");
		ow.ah.startMusic(TITLE_MUSIC_SLOT);
		for (;;) {
			Outcome o = playDemo(0, "intro", INTRO_DEMO_FRAMES, true, Integer.MAX_VALUE,
					new Coroutine("titles", this::titleSequence));
			if (o != Outcome.DEMO_OVER) return o == Outcome.DEMO_INTERRUPTED;

			for (Object[] d : DEMOS) {
				final String logo = (String) d[3];
				o = playDemo((Integer) d[0] - 1, (String) d[2], -1, false, (Integer) d[1],
						new Coroutine("demo " + d[2], co -> demoOverlay(co, logo)));
				if (o != Outcome.DEMO_OVER) return o == Outcome.DEMO_INTERRUPTED;
			}
		}
	}

	private Outcome playDemo(int level, String recording, int maxRecordingFrames, boolean loop, final int frames,
			final Coroutine overlay) {
		ow.reset();
		ow.levelNumber = level;
		byte[] rec = OpenableTools.mustLoad(TTResource.demo(recording));
		World w = new World(ow);
		final int[] frame = new int[1];
		w.configureDemo(new RecordedJoystick(rec, maxRecordingFrames, loop), () -> {
			frame[0]++;
			boolean more = overlay.step();
			return more && frame[0] < frames;
		});
		try (Coroutine c = overlay) {
			Outcome o = w.playLevel();
			System.out.println("FLOW: demo " + recording + " -> " + o);
			return stillInCharge() ? o : Outcome.TO_MAPPER;
		}
		finally {
			ow.reset();
		}
	}

	/**
	 * The title sequence. Runs as a coroutine, drawing over the demo: each
	 * {@link Coroutine#pause()} is one frame. Compare DSstart in s195.
	 */
	private void titleSequence(Coroutine co) {
		Dimmer dim = new Dimmer(0xa0);
		showLogo(co, dim, "0logotitle", 300);
		showText(co, dim, Texts.WRITTEN_BY, 220, true);
		showText(co, dim, Texts.THANKS_1, 180, true);
		showText(co, dim, Texts.THANKS_2, 180, true);
		showText(co, dim, Texts.THANKS_3, 180, true);
		showText(co, dim, Texts.highScores(highScores, null, null), 300, false);
		// back to the bare demo before handing over
		dim.target(0);
		while (!dim.isDone()) {
			dim.draw();
			co.pause();
		}
	}

	/** Over the world demos: the world's logo, then just the invitation. */
	private void demoOverlay(Coroutine co, String logo) {
		if (logo != null) showLogo(co, null, logo, 150);
		for (int f = 0;; f++) {
			drawPressToPlay(f);
			co.pause();
		}
	}

	// ---------------------------------------------------------------------------
	// TITLE SEQUENCE PIECES (all run inside a coroutine)

	private static final int FADE = 16;

	/** Darkens the game behind the titles; fades between levels of darkness. */
	private final class Dimmer {
		private final int darkest;
		private int current;
		private int target;

		Dimmer(int darkest) {
			this.darkest = darkest;
			this.target = darkest;
		}

		void target(int a) {
			target = a;
		}

		boolean isDone() {
			return current == target;
		}

		void draw() {
			int step = Math.max(1, darkest / FADE);
			if (current < target) current = Math.min(target, current + step);
			else if (current > target) current = Math.max(target, current - step);
			if (current > 0) gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), current << 24);
		}
	}

	/**
	 * Drop a picture in from the top, hold it, and lift it out.
	 * 
	 * @param dim
	 *            Darken the game behind it, or <code>null</code> not to.
	 */
	private void showLogo(Coroutine co, Dimmer dim, String name, int frames) {
		Sprite logo = loadPicture(name);
		try {
			int cx = gc.screenWidth() / 2;
			int cy = gc.screenHeight() / 2 - (dim != null ? 0 : 20);
			int top = -logo.h;
			for (int f = 0; f < frames; f++) {
				if (dim != null) dim.draw();
				int y;
				int fromEnd = frames - f;
				if (f < 25) y = top + (int) ((cy - top) * easeOut(f / 25f));
				else if (fromEnd < 20) y = cy + (int) ((top - cy) * easeIn((20 - fromEnd) / 20f));
				else y = cy;
				logo.drawByHandle(cx, y, false);
				// (the title picture fills the screen; no room for this on it)
				if (dim == null) drawPressToPlay(f);
				co.pause();
			}
		}
		finally {
			logo.dispose();
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

	/** A page of text, with a short blank either side of it. */
	private void showText(Coroutine co, Dimmer dim, String markup, int frames, boolean invite) {
		ScreenText text = new ScreenText(gc, font, markup);
		try {
			for (int f = 0; f < frames; f++) {
				dim.draw();
				if (f >= 6 && f < frames - 6) text.draw();
				if (invite) drawPressToPlay(f);
				co.pause();
			}
		}
		finally {
			text.dispose();
		}
	}

	private void drawPressToPlay(int f) {
		if ((f / 25) % 2 == 0) return;
		int w = font.computeWidth(0, PRESS_TO_PLAY);
		font.draw((gc.screenWidth() - w) / 2, gc.screenHeight() - 64, 0xffffff00, 0, PRESS_TO_PLAY);
	}

	private static float easeOut(float t) {
		t = Math.max(0, Math.min(1, t));
		return 1 - (1 - t) * (1 - t) * (1 - t);
	}

	private static float easeIn(float t) {
		t = Math.max(0, Math.min(1, t));
		return t * t * t;
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
		for (;;) {
			World world = new World(ow);
			if (ow.devPlayerStart != null) {
				world.configurePlayerStart(ow.devPlayerStart);
				ow.devPlayerStart = null;
			}
			Outcome o = world.playLevel();
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
				if (ow.levelNumber >= PersistedLevel.levelCount()) {
					ending();
					afterGame();
					return true;
				}
				break;
			case GAME_OVER:
				afterGame();
				return true;
			case LIFE_LOST:
			default:
				// same level again
				break;
			}
		}
	}

	private void afterGame() {
		HighScores.Entry e = highScores.add(ow.score);
		System.out.println("FLOW: game ended, score " + ow.score + (e != null ? " is a high score" : ""));
		if (e != null) {
			enterInitials(e);
			highScores.save();
			showScreen(Texts.highScores(highScores, e, null), 5 * 50, 2);
		}
	}

	// ---------------------------------------------------------------------------
	// THE ENDING

	private void ending() {
		ow.ah.loadMusic(TITLE_MUSIC_SLOT, "intro");
		ow.ah.startMusic(TITLE_MUSIC_SLOT);
		String[] pages = Texts.ending(ow.levelsCompleted, ow.gemsCollectedTotal);
		for (int i = 0; i < pages.length; i++) {
			showScreen(pages[i], 8 * 50, i % 8);
		}
		ow.ah.stopMusic();
	}

	// ---------------------------------------------------------------------------
	// SCREENS OF OUR OWN (outside any level)

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
	 * Show some text over a horizon until fire is pressed or time runs out, with
	 * a fade in and out.
	 */
	private void showScreen(String markup, int frames, int horizon) {
		ScreenText text = new ScreenText(gc, font, markup);
		Stick stick = new Stick();
		try {
			int out = -1;
			for (int f = 0; out < 0 || f - out < FADE; f++) {
				gc.beginDrawing();
				drainKeys();
				stick.read();
				if (out < 0 && (f >= frames || stick.pressed(Joystick.FIRE))) out = f;
				ow.getHorizon(horizon).draw();
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0x60000000);
				text.draw();
				int fade = out < 0 ? Math.max(0, FADE - f) : f - out;
				if (fade > 0) gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), (0xff * fade / FADE) << 24);
				gc.endDrawing();
			}
		}
		finally {
			text.dispose();
		}
	}

	private void drainKeys() {
		while (keyboard.nextEvent() != null) {
			// discard
		}
	}

	/**
	 * Let the player put their initials against their new high score. Type
	 * them, or use the stick: up/down to choose a letter, fire to take it,
	 * left to go back.
	 */
	private void enterInitials(HighScores.Entry e) {
		final String letters = "abcdefghijklmnopqrstuvwxyz0123456789.-!?";
		StringBuilder typed = new StringBuilder();
		int choice = 0;
		int repeat = 0;
		Stick stick = new Stick();
		ScreenText text = null;
		String shown = null;
		try {
			for (int f = 0;; f++) {
				gc.beginDrawing();
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
				String markup = Texts.enterInitials(highScores, e, typed + cursor);
				if (!markup.equals(shown)) {
					if (text != null) text.dispose();
					text = new ScreenText(gc, font, markup);
					shown = markup;
				}
				ow.getHorizon(3).draw();
				gc.fillRectangle(0, 0, gc.screenWidth(), gc.screenHeight(), 0x60000000);
				text.draw();
				gc.endDrawing();
				// (the table is shown again afterwards with the new entry in it)
				if (finished) return;
			}
		}
		finally {
			if (text != null) text.dispose();
			if (e.initials.isEmpty()) e.initials = "???";
		}
	}
}
