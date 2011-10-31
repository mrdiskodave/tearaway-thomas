package com.nney.tt;

import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.sprites.Anims;
import com.nney.tt.sprites.AnimsPool;
import com.nney.tt.sprites.Sprite;

public class GameOverDisplay implements LifeLostDevice {
	private final Sprite game;
	private final Sprite over;
	private final int mx;
	private final int my;
	private float gx;
	private float gv = 2f;
	private int timer = Const.FPS * 3;

	public GameOverDisplay(AnimsPool animsPool, GraphicsContext gc) {
		Anims ago = animsPool.expect("0gameover");
		game = ago.find("game").sprites[0];
		over = ago.find("over").sprites[0];

		mx = gc.screenWidth() / 2;
		my = gc.screenHeight() / 2;

		gx = mx + game.width() / 2 + 5;
	}

	@Override
	public void update() {
		gx -= gv;
		if (gx <= 0) {
			gx = 0;
			if (gv < 1f) {
				gv = 0;
				timer--;
			}
			gv = -gv * 0.5f;
		}
		else {
			gv += 0.6f;
		}
		int ix = (int) gx;
		game.drawByHandle(mx + ix, my, false);
		over.drawByHandle(mx - ix, my, false);
	}

	@Override
	public boolean isDone() {
		return timer <= 0;
	}
}
