package com.nney.tt.j2d;

import java.awt.Canvas;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Graphics2D;
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
import java.awt.image.VolatileImage;
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
 * for audio. No native libraries. (Or, with --lwjgl, the original LWJGL front
 * end.) The options are in {@link #USAGE}; -h or --help prints them.
 */
public class J2dMain {
	static {
		// On Windows, Java2D's Direct3D drawing took twice as long as its
		// OpenGL drawing (15ms a frame against 7.7ms full screen on David's
		// machine), so use OpenGL unless told otherwise. This has to happen
		// before anything starts AWT.
		if (System.getProperty("os.name", "").startsWith("Windows")
				&& System.getProperty("sun.java2d.opengl") == null) {
			System.setProperty("sun.java2d.opengl", "true");
		}
	}

	static final String USAGE = String.join(System.lineSeparator(), //
			"Tearaway Thomas", //
			"", //
			"Usage: java -jar tearaway-thomas.jar [options]", //
			"", //
			"  -h, --help           show this and stop", //
			"  --level N            skip the titles and start a game on level N (0 is the first)", //
			"  --scale N|full       window size: N times 400x300 (default 2), or full", //
			"                       screen (Alt+Enter or F11 switches, with Java2D)", //
			"  --mute               no sound", //
			"  --sound-device TEXT  play sound on the device with TEXT in its name (e.g.", //
			"                       realtek) instead of Windows' default", //
			"  --beep               sound test: a one second beep, and the sound devices", //
			"                       Java can see (with --lwjgl: through OpenAL)", //
			"  --lwjgl              use the original LWJGL front end (OpenGL and OpenAL,", //
			"                       Windows only) instead of Java2D; it takes --level,", //
			"                       --scale, --sound-device, --beep, --dev, --mapper,", //
			"                       --resources", //
			"", //
			"Developer options:", //
			"  --dev                developer keys: Esc quits, Tab opens the map editor,", //
			"                       D runs out the clock, N finishes the level", //
			"  --mapper             start in the map editor", //
			"  --resources DIR      read resources from DIR instead of from the jar", //
			"  --at X,Y             (with --level) start the player at this map position", //
			"  --demo NAME          (with --level) play a demo recording: intro, wood, toy,", //
			"                       ghost, ice, future", //
			"  --demo-frames N      (with --demo) stop the demo after N frames", //
			"", //
			"Headless testing (no window, runs as fast as possible):", //
			"  --headless", //
			"  --frames N           stop after N frames", //
			"  --capture DIR        save frames as PNGs into DIR", //
			"  --every K            ...one in every K frames (default 25)", //
			"  --input SCRIPT       scripted joystick, e.g. \"50:R,120:RF,200:-\": from frame", //
			"                       50 hold right, from 120 right and fire, from 200", //
			"                       nothing (U D L R F for the stick, lower case for keys)", //
			"  --wav FILE           also write the audio to a WAV file", //
			"", //
			"Keys: cursor keys (or Q A [ ]) to move, Space, Ctrl or Z to jump, P to pause,", //
			"Alt+Enter or F11 for full screen.");

	static final int W = J2dGraphicsContext.SCREEN_WIDTH;
	static final int H = J2dGraphicsContext.SCREEN_HEIGHT;

	// options
	boolean mapper;
	int level = -1;
	boolean dev;
	File resources;
	double scale = 2;
	boolean fullScreen;
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
	boolean beep;
	String soundDevice;

	public static void main(String[] args) throws Exception {
		java.util.List<String> rest = new java.util.ArrayList<String>(java.util.Arrays.asList(args));
		if (rest.contains("-h") || rest.contains("--help")) {
			System.out.println(USAGE);
			return;
		}
		if (rest.remove("--lwjgl")) {
			// the original OpenGL front end instead
			com.nney.tt.lwjgl.LwjglMain.main(rest.toArray(new String[0]));
			return;
		}
		J2dMain m = new J2dMain();
		try {
			m.parse(args);
		}
		catch (IllegalArgumentException | IndexOutOfBoundsException e) {
			badOptions(e);
		}
		if (m.beep) {
			JavaSoundBeep.run(m.soundDevice);
			return;
		}
		System.exit(m.run());
	}

	/** The window size for --scale: a number (2, 3, 2.5...) of times 400x300. */
	public static double parseScale(String v) {
		double s = Double.parseDouble(v);
		if (!(s >= 0.5 && s <= 20)) throw new IllegalArgumentException("--scale takes a number from 0.5 to 20, or full");
		return s;
	}

	/** A mistake in the options: say so briefly and stop. */
	public static void badOptions(RuntimeException e) {
		String why = e.getMessage();
		if (e instanceof IndexOutOfBoundsException) why = "An option is missing its value";
		else if (e instanceof NumberFormatException) why = "Not a number: " + why.replaceFirst("^For input string: ", "");
		System.err.println(why + " (--help lists the options)");
		System.exit(2);
	}

	void parse(String[] args) {
		for (int i = 0; i < args.length; i++) {
			String a = args[i];
			if (a.equals("--mapper")) mapper = true;
			else if (a.equals("--beep")) beep = true;
			else if (a.equals("--sound-device")) soundDevice = args[++i];
			else if (a.equals("--level")) level = Integer.parseInt(args[++i]);
			else if (a.equals("--dev")) dev = true;
			else if (a.equals("--resources")) resources = new File(args[++i]);
			else if (a.equals("--scale")) {
				String v = args[++i];
				if (v.equals("full")) fullScreen = true;
				else scale = parseScale(v);
			}
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
		final SoundAudioContext audio = new SoundAudioContext(!headless && !mute, soundDevice);
		final ScriptedJoystick script = inputScript == null ? null : new ScriptedJoystick(inputScript, keys);
		final Joystick joystick = script != null ? script : new KeyboardJoystick(keys);

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
			if (fullScreen) SwingUtilities.invokeAndWait(window::toggleFullScreen);
			presenter = window;
			pointer = new AwtPointer(window.canvas, window);
		}

		final AwtPointer finalPointer = pointer;
		final J2dGraphicsContext gc = new J2dGraphicsContext(new FrameClock(Const.FPS, !headless), presenter,
				() -> {
					keys.update();
					if (finalPointer != null) finalPointer.update();
					if (script != null) script.tick();
				});
		gcHolder[0] = gc;

		com.nney.tt.input.Pointer p = pointer != null ? pointer : new NullPointer();
		OuterWorld ow = new OuterWorld(gc, audio, joystick, keys, p);
		ow.devMode = dev || mapper;
		ow.devPlayerStart = startAt;
		if (mapper) ow.launchMapper(new Coord(0, 0));
		else if (demoName != null) {
			final String dn = demoName;
			ow.bootstrap = o -> {
				try (com.nney.tt.World w = new com.nney.tt.World(o)) {
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
		try (ow) {
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
			audio.close();
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

		Window(final AwtKeyboard keys, final double zoom) throws Exception {
			final JFrame[] f = new JFrame[1];
			final Canvas[] c = new Canvas[1];
			SwingUtilities.invokeAndWait(() -> {
				JFrame fr = new JFrame("Tearaway Thomas");
				Canvas cv = new Canvas();
				cv.setPreferredSize(new Dimension((int) Math.round(W * zoom), (int) Math.round(H * zoom)));
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
			});
			frame = f[0];
			canvas = c[0];
			bs = canvas.getBufferStrategy();
			System.out.println("Java2D drawing on the "
					+ (bs.getCapabilities().getBackBufferCapabilities().isAccelerated() ? "graphics card" : "processor")
					+ ("true".equals(System.getProperty("sun.java2d.opengl")) ? " with OpenGL" : ""));
		}

		/** The game's picture on the graphics card, so scaling it up happens there. */
		private VolatileImage onCard;

		/** Set when the window changes to or from full screen: new buffers needed. */
		private volatile boolean newBuffers;

		private boolean fullScreen;

		/**
		 * Full screen is a borderless window the size of the screen, not Java's
		 * exclusive full screen mode: that waits for the monitor's refresh (60Hz,
		 * say) every frame, which fights the game's 50Hz and makes frames late.
		 * Taking the border off means rebuilding the window, so not while a
		 * frame is being shown (see present()). Called on the AWT thread.
		 */
		void toggleFullScreen() {
			synchronized (this) {
				frame.dispose();
				if (fullScreen) {
					frame.setUndecorated(false);
					if (windowedBounds != null) frame.setBounds(windowedBounds);
				}
				else {
					windowedBounds = frame.getBounds();
					frame.setUndecorated(true);
					frame.setBounds(frame.getGraphicsConfiguration().getBounds());
				}
				fullScreen = !fullScreen;
				frame.setVisible(true);
				newBuffers = true;
			}
			canvas.requestFocus();
		}

		@Override
		public synchronized boolean present(BufferedImage frameImage) {
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

			if (newBuffers) {
				// (full screen can need buffers of its own)
				newBuffers = false;
				canvas.createBufferStrategy(2);
				bs = canvas.getBufferStrategy();
			}

			// Copy the small picture to the graphics card (120,000 pixels) and
			// scale it up there: scaling an image that changes every frame
			// straight onto the screen is done by the processor, a pixel at a
			// time, which is too slow full screen.
			do {
				if (onCard == null || onCard.validate(canvas.getGraphicsConfiguration()) == VolatileImage.IMAGE_INCOMPATIBLE) {
					onCard = canvas.createVolatileImage(W, H);
				}
				Graphics2D vg = onCard.createGraphics();
				vg.drawImage(frameImage, 0, 0, null);
				vg.dispose();
				do {
					do {
						Graphics2D g = (Graphics2D) bs.getDrawGraphics();
						// black bars around the picture (the picture covers the rest)
						g.setColor(Color.BLACK);
						Rectangle r = picture;
						if (r.y > 0) g.fillRect(0, 0, cw, r.y);
						if (r.y + r.height < ch) g.fillRect(0, r.y + r.height, cw, ch - r.y - r.height);
						if (r.x > 0) g.fillRect(0, r.y, r.x, r.height);
						if (r.x + r.width < cw) g.fillRect(r.x + r.width, r.y, cw - r.x - r.width, r.height);
						g.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
								RenderingHints.VALUE_INTERPOLATION_NEAREST_NEIGHBOR);
						g.drawImage(onCard, r.x, r.y, r.width, r.height, null);
						g.dispose();
					} while (bs.contentsRestored());
					bs.show();
				} while (bs.contentsLost());
			} while (onCard.contentsLost());
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
