package com.nney.tt.j2d;

import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.HashMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.nney.tt.input.Keyboard;
import com.nney.tt.input.PartialHasKeysImpl;

/**
 * Keyboard input from AWT.
 *
 * AWT delivers events on its own thread; we queue them and the game thread
 * picks them up in {@link #update()} once a frame, the same way the LWJGL
 * version polled.
 */
public class AwtKeyboard extends PartialHasKeysImpl implements Keyboard, KeyListener {
	private static final class Raw {
		final int key;
		final boolean down;
		final char ch;

		Raw(int key, boolean down, char ch) {
			this.key = key;
			this.down = down;
			this.ch = ch;
		}
	}

	private final HashMap<Integer, Integer> fromThem = new HashMap<Integer, Integer>();
	private final TreeSet<Integer> keys = new TreeSet<Integer>();
	private final ConcurrentLinkedQueue<Raw> incoming = new ConcurrentLinkedQueue<Raw>();
	private volatile boolean clearRequested;

	private void add(int theirKey, int ourKey) {
		fromThem.put(theirKey, ourKey);
	}

	public AwtKeyboard() {
		for (int i = 0; i < 26; i++) {
			add(KeyEvent.VK_A + i, KEY_A + i);
		}
		for (int i = 0; i < 10; i++) {
			add(KeyEvent.VK_0 + i, KEY_0 + i);
			add(KeyEvent.VK_NUMPAD0 + i, KEY_NUMPAD0 + i);
		}
		for (int i = 0; i < 12; i++) {
			add(KeyEvent.VK_F1 + i, KEY_F1 + i);
		}

		add(KeyEvent.VK_LEFT, KEY_LEFT);
		add(KeyEvent.VK_RIGHT, KEY_RIGHT);
		add(KeyEvent.VK_UP, KEY_UP);
		add(KeyEvent.VK_DOWN, KEY_DOWN);
		add(KeyEvent.VK_KP_LEFT, KEY_LEFT);
		add(KeyEvent.VK_KP_RIGHT, KEY_RIGHT);
		add(KeyEvent.VK_KP_UP, KEY_UP);
		add(KeyEvent.VK_KP_DOWN, KEY_DOWN);

		add(KeyEvent.VK_SHIFT, KEY_SHIFT);
		add(KeyEvent.VK_CONTROL, KEY_CONTROL);
		add(KeyEvent.VK_ALT, KEY_MENU);

		add(KeyEvent.VK_DIVIDE, KEY_DIVIDE);
		add(KeyEvent.VK_MULTIPLY, KEY_MULTIPLY);
		add(KeyEvent.VK_SUBTRACT, KEY_SUBTRACT);
		add(KeyEvent.VK_ADD, KEY_ADD);
		add(KeyEvent.VK_DECIMAL, KEY_DECIMAL);

		add(KeyEvent.VK_INSERT, KEY_INSERT);
		add(KeyEvent.VK_HOME, KEY_HOME);
		add(KeyEvent.VK_END, KEY_END);
		add(KeyEvent.VK_PAGE_UP, KEY_PRIOR);
		add(KeyEvent.VK_PAGE_DOWN, KEY_NEXT);
		add(KeyEvent.VK_DELETE, KEY_DELETE);

		add(KeyEvent.VK_ESCAPE, KEY_ESCAPE);
		add(KeyEvent.VK_BACK_QUOTE, KEY_GRAVE);
		add(KeyEvent.VK_MINUS, KEY_MINUS);
		add(KeyEvent.VK_EQUALS, KEY_EQUALS);
		add(KeyEvent.VK_BACK_SPACE, KEY_BACK);
		add(KeyEvent.VK_TAB, KEY_TAB);
		add(KeyEvent.VK_OPEN_BRACKET, KEY_LBRACKET);
		add(KeyEvent.VK_CLOSE_BRACKET, KEY_RBRACKET);
		add(KeyEvent.VK_ENTER, KEY_RETURN);
		add(KeyEvent.VK_SEMICOLON, KEY_SEMICOLON);
		add(KeyEvent.VK_QUOTE, KEY_APOSTROPHE);
		add(KeyEvent.VK_BACK_SLASH, KEY_BACKSLASH);
		add(KeyEvent.VK_COMMA, KEY_COMMA);
		add(KeyEvent.VK_PERIOD, KEY_PERIOD);
		add(KeyEvent.VK_SLASH, KEY_SLASH);
		add(KeyEvent.VK_SPACE, KEY_SPACE);
	}

	// --- AWT side (event thread) ---

	@Override
	public void keyPressed(KeyEvent e) {
		Integer ours = fromThem.get(e.getKeyCode());
		if (ours != null) {
			char c = e.getKeyChar();
			if (c == KeyEvent.CHAR_UNDEFINED) c = 0;
			incoming.add(new Raw(ours, true, c));
		}
		e.consume();
	}

	@Override
	public void keyReleased(KeyEvent e) {
		Integer ours = fromThem.get(e.getKeyCode());
		if (ours != null) {
			incoming.add(new Raw(ours, false, (char) 0));
		}
		e.consume();
	}

	@Override
	public void keyTyped(KeyEvent e) {
		e.consume();
	}

	/** Called when the window loses focus so keys don't get stuck down. */
	public void requestClear() {
		clearRequested = true;
	}

	// --- game side ---

	/** For scripted (headless) input. */
	public void inject(int ourKey, boolean down) {
		inject(ourKey, down, (char) 0);
	}

	/** For scripted (headless) input: a key that types a character. */
	public void inject(int ourKey, boolean down, char ch) {
		incoming.add(new Raw(ourKey, down, ch));
	}

	public void update() {
		if (clearRequested) {
			clearRequested = false;
			keys.clear();
		}
		Raw r;
		while ((r = incoming.poll()) != null) {
			if (r.down) {
				boolean repeat = keys.contains(r.key);
				if (repeat && r.key >= KEYBEGIN_SHIFTS && r.key <= KEYEND_SHIFTS) continue;
				keys.add(r.key);
				queueEvent(r.key, r.ch);
			}
			else {
				keys.remove(r.key);
			}
		}
	}

	@Override
	public boolean isDown(int key) {
		return keys.contains(key);
	}
}
