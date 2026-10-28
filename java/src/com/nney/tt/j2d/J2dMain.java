package com.nney.tt.j2d;

import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.GraphicsDevice;
import java.awt.GraphicsEnvironment;
import java.awt.Point;
import java.awt.Rectangle;
import java.awt.RenderingHints;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferStrategy;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.imageio.ImageIO;
import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import com.nney.tt.Const;
import com.nney.tt.OuterWorld;
import com.nney.tt.geom.Coord;
import com.nney.tt.input.Joystick;
import com.nney.tt.input.Keyboard;
import com.nney.tt.input.KeyboardJoystick;
import com.nney.tt.resources.TTResource;

/**
 * Starts Tearaway Thomas using only the JDK: Java2D for graphics, javax.sound
 * for audio. No native libraries.
 *
 * <pre>
 * Usage: J2dMain [options]
 *   --mapper             start in the map editor rather than the game
 *   --level N            skip the titles and start a game on level N (0 is the first)
 *   --dev                developer keys (Esc = mapper, D = run out the clock)
 *   --resources DIR      read resources from DIR instead of the classpath
 *   --scale N            initial window zoom (default 2)
 *   --mute               no sound
 *   --at X,Y             (with --level) start the player at this map position
 *   --lwjgl              use the original LWJGL (OpenGL + OpenAL) front end
 *                        instead; it takes --level, --dev, --mapper, --resources
 *
 * Headless testing (no window, runs as fast as possible):
 *   --headless
 *   --frames N           stop after N frames
 *   --capture DIR        save frames as PNGs into DIR
 *   --every K            ...one in every K frames (default 25)
 *   --input SCRIPT       scripted joystick, e.g. "50:R,120:RF,200:-" meaning
 *                        from frame 50 hold right, from 120 right+fire, from
 *                        200 nothing (letters: U D L R F)
 *   --wav FILE           also write the audio to a WAV file
 * </pre>
 */
public class J2dMain {
	static final int W = J2dGraphicsContext.SCREEN_WIDTH;
	static final int H = J2dGraphicsContext.SCREEN_HEIGHT;

	// options
	boolean mapper;
	int level = -1;
	boolean dev;
	File resources;
	int scale = 2;
	boolean mute;
	boolean headless;
	long maxFrames = -1;
	File captureDir;
	int every = 25;
	String inputScript;
	File wavFile;
	String demoName;
	Coord startAt;
	long demoFrames = -1;

	public static void main(String[] args) throws Exception {
		java.util.List<String> rest = new java.util.ArrayList<String>(java.util.Arrays.asList(args));
		if (rest.remove("--lwjgl")) {
			// the original OpenGL front end instead
			com.nney.tt.lwjgl.LwjglMain.main(rest.toArray(new String[0]));
			return;
		}
		J2dMain m = new J2dMain();
		m.parse(args);
		System.exit(m.run());
	}

	void parse(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String a = args[i];
			if (a.equals("--mapper")) mapper = true;
			else if (a.equals("--level")) level = Integer.parseInt(args[++i]);
			else if (a.equals("--dev")) dev = true;
			else if (a.equals("--resources")) resources = new File(args[++i]);
			else if (a.equals("--scale")) scale = Integer.parseInt(args[++i]);
			else if (a.equals("--mute")) mute = true;
			else if (a.equals("--headless")) headless = true;
			else if (a.equals("--frames")) maxFrames = Long.parseLong(args[++i]);
			else if (a.equals("--capture")) captureDir = new File(args[++i]);
			else if (a.equals("--every")) every = Integer.parseInt(args[++i]);
			else if (a.equals("--input")) inputScript = args[++i];
			else if (a.equals("--wav")) wavFile = new File(args[++i]);
			else if (a.equals("--demo")) demoName = args[++i];
			else if (a.equals("--at")) {
				String[] xy = args[++i].split(",");
				startAt = new Coord(Integer.parseInt(xy[0].trim()), Integer.parseInt(xy[1].trim()));
			}
			else if (a.equals("--demo-frames")) demoFrames = Long.parseLong(args[++i]);
			else throw new IllegalArgumentException("Unknown option: " + a);
		}
		if (GraphicsEnvironment.isHeadless()) headless = true;
	}

	int run() throws Exception {
		if (resources != null) TTResource.setResourcePath(resources);

		final AwtKeyboard keys = new AwtKeyboard();
		final SoundAudioContext audio = new SoundAudioContext(!headless && !mute);
		final ScriptedJoystick script = inputScript == null ? null : new ScriptedJoystick(inputScript, keys);
		final Joystick joystick = script != null ? script : new ArrowsAndKeysJoystick(keys);

		final J2dGraphicsContext[] gcHolder = new J2dGraphicsContext[1];
		J2dGraphicsContext.Presenter presenter;
		AwtPointer pointer;
		final Window window;

		if (headless) {
			window = null;
			presenter = new HeadlessPresenter(gcHolder, audio);
			pointer = null;
		}
		else {
			window = new Window(keys, scale);
			presenter = window;
			pointer = new AwtPointer(window.canvas, window);
		}

		final AwtPointer finalPointer = pointer;
		final J2dGraphicsContext gc = new J2dGraphicsContext(new FrameClock(Const.FPS, !headless), presenter,
				new Runnable() {
					@Override
					public void run() {
						keys.update();
						if (finalPointer != null) finalPointer.update();
						if (script != null) script.tick();
					}
				});
		gcHolder[0] = gc;

		com.nney.tt.input.Pointer p = pointer != null ? pointer : new NullPointer();
		OuterWorld ow = new OuterWorld(gc, audio, joystick, keys, p);
		ow.devMode = dev || mapper;
		ow.devPlayerStart = startAt;
		if (mapper) ow.launchMapper(new Coord(0, 0));
		else if (demoName != null) {
			final String dn = demoName;
			ow.bootstrap = new com.nney.tt.Launcher() {
				@Override
				public void launch(OuterWorld o) {
					com.nney.tt.World w = new com.nney.tt.World(o);
					byte[] rec = com.nney.utils.OpenableTools.mustLoad(TTResource.demo(dn));
					final long limit = demoFrames > 0 ? demoFrames : Long.MAX_VALUE;
					final long start = gcHolder[0].frameCount();
					w.configureDemo(new com.nney.tt.input.RecordedJoystick(rec, -1, false),
							() -> gcHolder[0].frameCount() - start < limit);
					com.nney.tt.World.Outcome outc = w.playLevel();
					System.out.println("Demo " + dn + ": " + outc + " after " + (gcHolder[0].frameCount() - start)
							+ " frames" + (gcHolder[0].frameCount() - start >= limit ? " (time limit)" : " (early!)"));
					throw new J2dGraphicsContext.QuitRequested();
				}
			};
		}
		else ow.launchFullGame(level);

		int rc = 0;
		try {
			ow.run();
		}
		catch (J2dGraphicsContext.QuitRequested q) {
			// window closed or frame limit reached
		}
		catch (RuntimeException e) {
			e.printStackTrace();
			rc = 1;
		}
		finally {
			if (presenter instanceof HeadlessPresenter) ((HeadlessPresenter) presenter).finish();
			audio.dispose();
			if (window != null) window.close();
		}
		return rc;
	}

	// ---------------------------------------------------------------------------

	/** The game window. Keeps the 4:3 picture centred whatever its size. */
	final class Window implements J2dGraphicsContext.Presenter, AwtPointer.Mapping {
		final JFrame frame;
		final Canvas canvas;
		volatile boolean closeRequested;
		private BufferStrategy bs;
		private Rectangle picture = new Rectangle(0, 0, W, H);
		private Rectangle windowedBounds;

		Window(final AwtKeyboard keys, final int zoom) throws Exception {
			final JFrame[] f = new JFrame[1];
			final Canvas[] c = new Canvas[1];
			SwingUtilities.invokeAndWait(new Runnable() {
				@Override
				public void run() {
					JFrame fr = new JFrame("Tearaway Thomas");
					Canvas cv = new Canvas();
					cv.setPreferredSize(new Dimension(W * zoom, H * zoom));
					cv.setBackground(Color.BLACK);
					cv.setFocusTraversalKeysEnabled(false);
					cv.addKeyListener(keys);
					cv.addKeyListener(new KeyAdapter() {
						@Override
						public void keyPressed(KeyEvent e) {
							boolean altEnter = e.getKeyCode() == KeyEvent.VK_ENTER && e.isAltDown();
							if (altEnter || e.getKeyCode() == KeyEvent.VK_F11) toggleFullScreen();
						}
					});
					cv.addFocusListener(new FocusAdapter() {
						@Override
						public void focusLost(FocusEvent e) {
							keys.requestClear();
						}
					});
					fr.add(cv);
					fr.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
					fr.addWindowListener(new WindowAdapter() {
						@Override
						public void windowClosing(WindowEvent e) {
							closeRequested = true;
						}
					});
					fr.pack();
					fr.setLocationRelativeTo(null);
					fr.setVisible(true);
					cv.createBufferStrategy(2);
					cv.requestFocus();
					f[0] = fr;
					c[0] = cv;
				}
			});
			frame = f[0];
			canvas = c[0];
			bs = canvas.getBufferStrategy();
		}

		void toggleFullScreen() {
			GraphicsDevice gd = frame.getGraphicsConfiguration().getDevice();
			if (gd.getFullScreenWindow() == frame) {
				gd.setFullScreenWindow(null);
				if (windowedBounds != null) frame.setBounds(windowedBounds);
			}
			else {
				windowedBounds = frame.getBounds();
				gd.setFullScreenWindow(frame);
			}
			canvas.requestFocus();
		}

		@Override
		public boolean present(BufferedImage frameImage) {
			if (closeRequested) return false;
			int cw = canvas.getWidth();
			int ch = canvas.getHeight();
			if (cw <= 0 || ch <= 0) return true;

			// biggest 4:3 rectangle that fits; whole-number zoom if it's close
			double s = Math.min((double) cw / W, (double) ch / H);
			if (s >= 1 && s - Math.floor(s) < 0.15) s = Math.floor(s);
			int pw = (int) (W * s);
			int ph = (int) (H * s);
			picture = new Rectangle((cw - pw) / 2, (ch - ph) / 2, pw, ph);

			do {
				do {
					Graphics2D g = (Graphics2D) bs.getDrawGraphics();
					g.setColor(Color.BLACK);
					g.fillRect(0, 0, cw, ch);
					g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
							RenderingHints.VALUE_INTERPOLATION_NEAREST_NEIGHBOR);
					g.drawImage(frameImage, picture.x, picture.y, picture.width, picture.height, null);
					g.dispose();
				} while (bs.contentsRestored());
				bs.show();
			} while (bs.contentsLost());
			java.awt.Toolkit.getDefaultToolkit().sync();
			return true;
		}

		@Override
		public Point toGame(int wx, int wy) {
			Rectangle p = picture;
			int gx = (int) ((wx - p.x) * (long) W / Math.max(1, p.width));
			int gy = (int) ((wy - p.y) * (long) H / Math.max(1, p.height));
			return new Point(Math.max(0, Math.min(W - 1, gx)), Math.max(0, Math.min(H - 1, gy)));
		}

		@Override
		public Point toWindow(int gx, int gy) {
			Rectangle p = picture;
			return new Point(p.x + gx * p.width / W, p.y + gy * p.height / H);
		}

		void close() {
			frame.dispose();
		}
	}

	/** Saves frames to disk instead of showing them. */
	final class HeadlessPresenter implements J2dGraphicsContext.Presenter {
		private final J2dGraphicsContext[] gc;
		private final SoundAudioContext audio;
		private final List<short[]> audioChunks = new ArrayList<short[]>();
		private long n;

		HeadlessPresenter(J2dGraphicsContext[] gc, SoundAudioContext audio) {
			this.gc = gc;
			this.audio = audio;
			if (captureDir != null) captureDir.mkdirs();
		}

		@Override
		public boolean present(BufferedImage frame) {
			if (wavFile != null) {
				int perFrame = SoundAudioContext.RATE / Const.FPS;
				short[] chunk = new short[perFrame * 2];
				audio.mix(chunk, perFrame);
				audioChunks.add(chunk);
			}
			if (captureDir != null && n % every == 0) {
				try {
					ImageIO.write(frame, "png", new File(captureDir, String.format("f%06d.png", n)));
				}
				catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
			n++;
			return maxFrames < 0 || n < maxFrames;
		}

		void finish() {
			System.out.println("Frames rendered: " + n);
			if (wavFile != null) {
				int total = 0;
				for (short[] c : audioChunks)
					total += c.length;
				short[] all = new short[total];
				int p = 0;
				for (short[] c : audioChunks) {
					System.arraycopy(c, 0, all, p, c.length);
					p += c.length;
				}
				byte[] bytes = new byte[all.length * 2];
				for (int i = 0; i < all.length; i++) {
					bytes[i * 2] = (byte) all[i];
					bytes[i * 2 + 1] = (byte) (all[i] >> 8);
				}
				javax.sound.sampled.AudioFormat fmt = new javax.sound.sampled.AudioFormat(SoundAudioContext.RATE, 16, 2,
						true, false);
				try {
					javax.sound.sampled.AudioSystem.write(new javax.sound.sampled.AudioInputStream(
							new java.io.ByteArrayInputStream(bytes), fmt, all.length / 2),
							javax.sound.sampled.AudioFileFormat.Type.WAVE, wavFile);
				}
				catch (IOException e) {
					throw new RuntimeException(e);
				}
			}
		}
	}

	/** The original keys (Q A [ ] space) plus cursor keys with Ctrl/Space/Z to fire. */
	static final class ArrowsAndKeysJoystick implements Joystick {
		private final Keyboard k;
		private final KeyboardJoystick classic;

		ArrowsAndKeysJoystick(Keyboard k) {
			this.k = k;
			this.classic = new KeyboardJoystick(k);
		}

		@Override
		public int get() {
			int x = classic.get();
			if (k.isDown(Keyboard.KEY_UP)) x |= UP;
			if (k.isDown(Keyboard.KEY_DOWN)) x |= DOWN;
			if (k.isDown(Keyboard.KEY_LEFT)) x |= LEFT;
			if (k.isDown(Keyboard.KEY_RIGHT)) x |= RIGHT;
			if (k.isDown(Keyboard.KEY_CONTROL) || k.isDown(Keyboard.KEY_Z)) x |= FIRE;
			return x;
		}
	}

	/**
	 * Joystick (and keyboard) driven by a script, for automated tests.
	 * "50:R,120:RF,200:-,300:n,302:-" means: from frame 50 hold right, from 120
	 * right and fire, from 200 nothing, from 300 hold the N key... Upper case
	 * U D L R F are the stick; lower case letters are keys.
	 */
	static final class ScriptedJoystick implements Joystick {
		private final long[] at;
		private final int[] value;
		private final String[] keys;
		private final AwtKeyboard keyboard;
		private long frame = -1;
		private int current;
		private String currentKeys = "";
		private int idx;

		ScriptedJoystick(String script, AwtKeyboard keyboard) {
			this.keyboard = keyboard;
			String[] parts = script.split(",");
			at = new long[parts.length];
			value = new int[parts.length];
			keys = new String[parts.length];
			for (int i = 0; i < parts.length; i++) {
				String[] kv = parts[i].trim().split(":");
				at[i] = Long.parseLong(kv[0]);
				int v = 0;
				StringBuilder k = new StringBuilder();
				for (char c : kv[1].toCharArray()) {
					if (c == 'U') v |= UP;
					else if (c == 'D') v |= DOWN;
					else if (c == 'L') v |= LEFT;
					else if (c == 'R') v |= RIGHT;
					else if (c == 'F') v |= FIRE;
					else if (c >= 'a' && c <= 'z') k.append(c);
				}
				value[i] = v;
				keys[i] = k.toString();
			}
		}

		void tick() {
			frame++;
			while (idx < at.length && at[idx] <= frame) {
				current = value[idx];
				for (char c : currentKeys.toCharArray())
					keyboard.inject(Keyboard.KEY_A + (c - 'a'), false);
				currentKeys = keys[idx];
				for (char c : currentKeys.toCharArray())
					keyboard.inject(Keyboard.KEY_A + (c - 'a'), true, c);
				idx++;
			}
		}

		@Override
		public int get() {
			return current;
		}
	}

	static final class NullPointer extends com.nney.tt.input.PartialPointerImpl {
		@Override
		public void set(int x, int y) {
		}
	}
}
