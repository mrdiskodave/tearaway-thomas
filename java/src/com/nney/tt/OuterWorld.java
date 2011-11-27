package com.nney.tt;

import java.util.ArrayList;

import com.nney.tt.gfx.Disposable;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.MultiDisposable;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
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
	public DisposableField<BlockSet> blockSet = new DisposableField<BlockSet>();

	public final Pointer mouse;

	// 31 "i0"
	// 3 "worm"
	public int levelNumber = 12;

	public int score = 0;

	public int lives = 3;

	private MultiDisposable md = new MultiDisposable();

	public ArrayList<Horizon> horizons = new ArrayList<Horizon>();

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
	public void dispose() {
		md.dispose();
	}

	public boolean firstLevel() {
		return levelNumber == 0;
	}

	public boolean lastLevel() {
		return levelNumber == PersistedLevel.levelCount() - 1;
	}
}
