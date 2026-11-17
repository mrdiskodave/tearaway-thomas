package com.nney.tt;

import java.util.ArrayList;

import com.nney.tt.geom.Coord;
import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.mapper.Mapper;
import com.nney.tt.resources.TTResource;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.AudioHub;
import com.nney.tt.sprites.AnimsDefPool;
import com.nney.tt.sprites.AnimsPool;

public class OuterWorld implements Runnable, Disposable {
	static public class ExitException extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}

	public final AudioHub ah;

	public final Fonts fonts;

	public final GraphicsContext gc;

	public final Joystick joystick;

	public final Keyboard keyboard;

	// Disposable:
	public final AnimsPool animsPool;

	// Disposable:
	public DisposableField<BlockSet> blockSet = new DisposableField<>();

	public final Pointer mouse;

	// 31 "i0"
	// 3 "worm"
	// 10 car ferry
	// 14 toy fruit
	public int levelNumber = 0;

	public int score = 0;

	public int lives = 3;

	/** For the end-of-game statistics. */
	public int levelsCompleted = 0;

	/** For the end-of-game statistics. */
	public int gemsCollectedTotal = 0;

	/**
	 * Found a level's secret (fruit_entry in the original): the next bonus
	 * stage gets played.
	 */
	public boolean secretBonusFound = false;

	/** Did they collect the star on the stage just completed? */
	public boolean starCollected;

	/** The world whose logo was shown last (blkset_logoed in s195); null for none. */
	public String worldLogoShown;

	/** Developers: start the next level with the player here (or null). */
	public Coord devPlayerStart;

	private MultiDisposable md = new MultiDisposable();

	public ArrayList<Horizon> horizons = new ArrayList<>();

	public OuterWorld(GraphicsContext gc, AudioContext ac, Joystick joystick, Keyboard keyboard, Pointer mouse) {
		this.gc = gc;
		this.joystick = joystick;
		this.keyboard = keyboard;
		this.mouse = mouse;

		ah = new AudioHub(ac);
		fonts = new Fonts(gc);
		animsPool = new AnimsPool(gc, new AnimsDefPool());
		md.addMany(fonts, animsPool, blockSet);

		for (int x = 0; x < 8; x++) {
			Horizon h = gc.loadHorizon(TTResource.horizon(x));
			horizons.add(h);
			md.add(h);
		}
	}

	public void reset() {
		levelNumber = 0;
		score = 0;
		lives = 3;
		levelsCompleted = 0;
		gemsCollectedTotal = 0;
		secretBonusFound = false;
	}

	public BlockSet loadBlockSet(BlockSet.Config config) {
		if (blockSet.empty() || !blockSet.get().isSame(config)) {
			blockSet.set(BlockSet.createBlockSet(gc, config));
		}
		return blockSet.get();
	}

	public Horizon getHorizon(int n) {
		return horizons.get(n);
	}

	public Launcher bootstrap;

	public boolean devMode;

	public void resetStats() {
		lives = 3;
		score = 0;
	}

	@Override
	public void run() {
		try {
			for (;;) {
				bootstrap.launch(this);
			}
		}
		catch (ExitException ex) {
		}
	}

	@Override
	public void close() {
		md.close();
	}

	public boolean firstLevel() {
		return levelNumber == 0;
	}

	public boolean lastLevel() {
		return levelNumber == PersistedLevel.levelCount() - 1;
	}

	public void launchMapper(Coord initialScreenStart) {
		final Coord c2 = initialScreenStart.copy();
		bootstrap = new Launcher() {
			private Coord c = c2.copy();

			@Override
			public void launch(OuterWorld outerWorld) {
				new Mapper(outerWorld, c).run();
				c = null;
			}
		};
	}

	/**
	 * The whole game: title sequence and demos, play, game over, high scores,
	 * round and round.
	 */
	public void launchFullGame(int startLevel) {
		bootstrap = new com.nney.tt.flow.GameFlow(startLevel);
	}

	public void launchGame() {
		bootstrap = outerWorld -> {
			try (World w = new World(outerWorld)) {
				w.playLevel();
			}
		};
	}

}
