package com.nney.tt.j2d;

import java.awt.AlphaComposite;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.image.BufferedImage;
import java.util.ArrayDeque;

import com.nney.tt.gfx.Blitable;
import com.nney.tt.gfx.BlockSource;
import com.nney.tt.gfx.BlocksHolder;
import com.nney.tt.gfx.Font;
import com.nney.tt.gfx.GraphicsContext;
import com.nney.tt.gfx.Horizon;
import com.nney.tt.gfx.RawFont;
import com.nney.tt.gfx.SimpleImage;
import com.nney.utils.Openable;
import com.nney.utils.OpenableTools;

/**
 * A {@link GraphicsContext} that draws into an off-screen 400x300 image with
 * Java2D. Each finished frame is handed to a {@link Presenter}, which puts it
 * in a window (or saves it, when running headless).
 */
public final class J2dGraphicsContext implements GraphicsContext {
	public static final int SCREEN_WIDTH = 400;
	public static final int SCREEN_HEIGHT = 300;

	/** Where finished frames go. */
	public interface Presenter {
		/**
		 * Show a finished frame.
		 *
		 * @return <code>false</code> if the user has asked to quit.
		 */
		boolean present(BufferedImage frame);
	}

	private final BufferedImage screen = new BufferedImage(SCREEN_WIDTH, SCREEN_HEIGHT, BufferedImage.TYPE_INT_RGB);
	private final ArrayDeque<Graphics2D> targets = new ArrayDeque<Graphics2D>();
	private final Presenter presenter;
	private final Runnable updateInputs;
	private final FrameClock clock;

	private Graphics2D screenG;
	private boolean inside;
	private long frameCount;

	public J2dGraphicsContext(FrameClock clock, Presenter presenter, Runnable updateInputs) {
		this.clock = clock;
		this.presenter = presenter;
		this.updateInputs = updateInputs;
	}

	/** The surface that drawing currently goes to. */
	Graphics2D g() {
		Graphics2D g = targets.peek();
		if (g != null) return g;
		if (screenG == null) {
			// someone drawing outside begin/end: give them the screen anyway
			screenG = newScreenGraphics();
		}
		return screenG;
	}

	void pushTarget(Graphics2D g) {
		targets.push(g);
	}

	void popTarget() {
		targets.pop();
	}

	private Graphics2D newScreenGraphics() {
		Graphics2D g = screen.createGraphics();
		g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_NEAREST_NEIGHBOR);
		g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_OFF);
		g.setComposite(AlphaComposite.SrcOver);
		return g;
	}

	public long frameCount() {
		return frameCount;
	}

	@Override
	public void beginDrawing() {
		assert !inside;
		inside = true;
		clock.waitForNextFrame();
		updateInputs.run();
		if (screenG == null) screenG = newScreenGraphics();
		// the OpenGL version cleared to this colour; anything not drawn shows it
		screenG.setColor(new Color(0x0080ff));
		screenG.fillRect(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT);
	}

	private boolean quit;

	@Override
	public void requestQuit() {
		quit = true;
	}

	@Override
	public void endDrawing() {
		assert inside;
		inside = false;
		frameCount++;
		if (!presenter.present(screen) || quit) {
			throw new QuitRequested();
		}
	}

	@Override
	public void fillRectangle(int x, int y, int w, int h, int col) {
		if (w <= 0 || h <= 0) return;
		Graphics2D g = g();
		g.setColor(new Color(col, true));
		g.fillRect(x, y, w, h);
	}

	@Override
	public Blitable createBlitable(SimpleImage i) {
		return new J2dImage(this, i);
	}

	@Override
	public BlocksHolder createBlocksHolder(BlockSource bs) {
		return new J2dBlocksHolder(this, bs);
	}

	@Override
	public Font createFont(RawFont rf) {
		return new J2dFont(this, rf);
	}

	@Override
	public int screenWidth() {
		return SCREEN_WIDTH;
	}

	@Override
	public int screenHeight() {
		return SCREEN_HEIGHT;
	}

	@Override
	public Horizon loadHorizon(Openable ho) {
		final BufferedImage bi = J2dImage.toBufferedImage(new SimpleImage(OpenableTools.mustLoad(ho)));
		return new Horizon() {
			@Override
			public void draw() {
				Graphics2D g = g();
				Object old = g.getRenderingHint(RenderingHints.KEY_INTERPOLATION);
				g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
				g.drawImage(bi, 0, 0, SCREEN_WIDTH, SCREEN_HEIGHT, null);
				if (old != null) g.setRenderingHint(RenderingHints.KEY_INTERPOLATION, old);
			}

			@Override
			public void dispose() {
				bi.flush();
			}
		};
	}

	/**
	 * Fill everything <b>outside</b> a circle with a colour (the "iris"
	 * transition between levels).
	 */
	@Override
	public void aperture(int radius, int x, int y, int c) {
		Graphics2D g = g();
		Area outside = new Area(new java.awt.Rectangle(0, 0, SCREEN_WIDTH, SCREEN_HEIGHT));
		if (radius > 0) {
			outside.subtract(new Area(new Ellipse2D.Float(x - radius, y - radius, radius * 2, radius * 2)));
		}
		g.setColor(new Color(c, true));
		g.fill(outside);
	}

	/** Thrown from {@link #endDrawing()} when the window is closed. */
	public static class QuitRequested extends RuntimeException {
		private static final long serialVersionUID = 1L;
	}
}
