package com.nney.tt;

import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.Pointer;
import com.nney.tt.sounds.AudioContext;
import com.nney.tt.sounds.AudioHub;
import com.nney.tt.sprites.AnimsDefPool;
import com.nney.tt.sprites.AnimsPool;

public class OuterWorld implements Runnable {
	public final AudioHub ah;

	public final Fonts fonts;

	public final GraphicsContext gc;

	public final Joystick joystick;

	public final Keyboard keyboard;

	// Disposable:
	public final AnimsPool animsPool;

	// Disposable:
	public BlockSet blockSet;

	public final Pointer mouse;

	public int levelNumber = 6;

	public int score = 0;

	public int lives = 3;

	public OuterWorld(GraphicsContext gc, AudioContext ac, Joystick joystick, Keyboard keyboard, Pointer mouse) {
		this.gc = gc;
		this.joystick = joystick;
		this.keyboard = keyboard;
		this.mouse = mouse;

		ah = new AudioHub(ac);
		fonts = new Fonts(gc);
		animsPool = new AnimsPool(gc, new AnimsDefPool());
	}
	
	public void reset() {
		levelNumber = 0;
		score = 0;
		lives = 3;
	}

	public BlockSet loadBlockSet(BlockSet.Config config) {
		if (blockSet == null || !blockSet.isSame(config)) {
			freeBlocksSet();
			blockSet = new BlockSet(gc, config);
		}
		return blockSet;
	}

	private void freeBlocksSet() {
		if (blockSet != null) {
			blockSet.dispose();
			blockSet = null;
		}
	}

	public Launcher bootstrap;

	@Override
	public void run() {
		for (;;) {
			bootstrap.launch(this);
		}
	}
}
