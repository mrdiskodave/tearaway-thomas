package com.nney.tt.lwjgl;

import java.util.HashMap;
import java.util.TreeSet;

import com.nney.tt.input.Keyboard;
import com.nney.tt.input.PartialHasKeysImpl;

public class LwjglKeyboard extends PartialHasKeysImpl implements Keyboard {
	private HashMap<Integer, Integer> fromThem = new HashMap<Integer, Integer>();
	private TreeSet<Integer> keys = new TreeSet<Integer>();

	private void add(int theirKey, int ourKey) {
		fromThem.put(theirKey, ourKey);
	}

	public LwjglKeyboard() {

		// regular keys
		add(org.lwjgl.input.Keyboard.KEY_A, KEY_A);
		add(org.lwjgl.input.Keyboard.KEY_B, KEY_B);
		add(org.lwjgl.input.Keyboard.KEY_C, KEY_C);
		add(org.lwjgl.input.Keyboard.KEY_D, KEY_D);
		add(org.lwjgl.input.Keyboard.KEY_E, KEY_E);
		add(org.lwjgl.input.Keyboard.KEY_F, KEY_F);
		add(org.lwjgl.input.Keyboard.KEY_G, KEY_G);
		add(org.lwjgl.input.Keyboard.KEY_H, KEY_H);
		add(org.lwjgl.input.Keyboard.KEY_I, KEY_I);
		add(org.lwjgl.input.Keyboard.KEY_J, KEY_J);
		add(org.lwjgl.input.Keyboard.KEY_K, KEY_K);
		add(org.lwjgl.input.Keyboard.KEY_L, KEY_L);
		add(org.lwjgl.input.Keyboard.KEY_M, KEY_M);
		add(org.lwjgl.input.Keyboard.KEY_N, KEY_N);
		add(org.lwjgl.input.Keyboard.KEY_O, KEY_O);
		add(org.lwjgl.input.Keyboard.KEY_P, KEY_P);
		add(org.lwjgl.input.Keyboard.KEY_Q, KEY_Q);
		add(org.lwjgl.input.Keyboard.KEY_R, KEY_R);
		add(org.lwjgl.input.Keyboard.KEY_S, KEY_S);
		add(org.lwjgl.input.Keyboard.KEY_T, KEY_T);
		add(org.lwjgl.input.Keyboard.KEY_U, KEY_U);
		add(org.lwjgl.input.Keyboard.KEY_V, KEY_V);
		add(org.lwjgl.input.Keyboard.KEY_W, KEY_W);
		add(org.lwjgl.input.Keyboard.KEY_X, KEY_X);
		add(org.lwjgl.input.Keyboard.KEY_Y, KEY_Y);
		add(org.lwjgl.input.Keyboard.KEY_Z, KEY_Z);
		add(org.lwjgl.input.Keyboard.KEY_0, KEY_0);
		add(org.lwjgl.input.Keyboard.KEY_1, KEY_1);
		add(org.lwjgl.input.Keyboard.KEY_2, KEY_2);
		add(org.lwjgl.input.Keyboard.KEY_3, KEY_3);
		add(org.lwjgl.input.Keyboard.KEY_4, KEY_4);
		add(org.lwjgl.input.Keyboard.KEY_5, KEY_5);
		add(org.lwjgl.input.Keyboard.KEY_6, KEY_6);
		add(org.lwjgl.input.Keyboard.KEY_7, KEY_7);
		add(org.lwjgl.input.Keyboard.KEY_8, KEY_8);
		add(org.lwjgl.input.Keyboard.KEY_9, KEY_9);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD0, KEY_NUMPAD0);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD1, KEY_NUMPAD1);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD2, KEY_NUMPAD2);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD3, KEY_NUMPAD3);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD4, KEY_NUMPAD4);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD5, KEY_NUMPAD5);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD6, KEY_NUMPAD6);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD7, KEY_NUMPAD7);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD8, KEY_NUMPAD8);
		add(org.lwjgl.input.Keyboard.KEY_NUMPAD9, KEY_NUMPAD9);
		add(org.lwjgl.input.Keyboard.KEY_F1, KEY_F1);
		add(org.lwjgl.input.Keyboard.KEY_F2, KEY_F2);
		add(org.lwjgl.input.Keyboard.KEY_F3, KEY_F3);
		add(org.lwjgl.input.Keyboard.KEY_F4, KEY_F4);
		add(org.lwjgl.input.Keyboard.KEY_F5, KEY_F5);
		add(org.lwjgl.input.Keyboard.KEY_F6, KEY_F6);
		add(org.lwjgl.input.Keyboard.KEY_F7, KEY_F7);
		add(org.lwjgl.input.Keyboard.KEY_F8, KEY_F8);
		add(org.lwjgl.input.Keyboard.KEY_F9, KEY_F9);
		add(org.lwjgl.input.Keyboard.KEY_F10, KEY_F10);
		add(org.lwjgl.input.Keyboard.KEY_F11, KEY_F11);
		add(org.lwjgl.input.Keyboard.KEY_F12, KEY_F12);

		// cursor keys
		add(org.lwjgl.input.Keyboard.KEY_LEFT, KEY_LEFT);
		add(org.lwjgl.input.Keyboard.KEY_RIGHT, KEY_RIGHT);
		add(org.lwjgl.input.Keyboard.KEY_UP, KEY_UP);
		add(org.lwjgl.input.Keyboard.KEY_DOWN, KEY_DOWN);

		// shift keys
		add(org.lwjgl.input.Keyboard.KEY_LSHIFT, KEY_SHIFT);
		add(org.lwjgl.input.Keyboard.KEY_RSHIFT, KEY_SHIFT);
		add(org.lwjgl.input.Keyboard.KEY_LCONTROL, KEY_CONTROL);
		add(org.lwjgl.input.Keyboard.KEY_RCONTROL, KEY_CONTROL);
		add(org.lwjgl.input.Keyboard.KEY_LMENU, KEY_MENU);
		add(org.lwjgl.input.Keyboard.KEY_RMENU, KEY_MENU);

		// round the numeric keypad
		add(org.lwjgl.input.Keyboard.KEY_DIVIDE, KEY_DIVIDE);
		add(org.lwjgl.input.Keyboard.KEY_MULTIPLY, KEY_MULTIPLY);
		add(org.lwjgl.input.Keyboard.KEY_SUBTRACT, KEY_SUBTRACT);
		add(org.lwjgl.input.Keyboard.KEY_ADD, KEY_ADD);
		add(org.lwjgl.input.Keyboard.KEY_DECIMAL, KEY_DECIMAL);

		// the navigation cluster
		add(org.lwjgl.input.Keyboard.KEY_INSERT, KEY_INSERT);
		add(org.lwjgl.input.Keyboard.KEY_HOME, KEY_HOME);
		add(org.lwjgl.input.Keyboard.KEY_END, KEY_END);
		add(org.lwjgl.input.Keyboard.KEY_PRIOR, KEY_PRIOR);
		add(org.lwjgl.input.Keyboard.KEY_NEXT, KEY_NEXT);
		add(org.lwjgl.input.Keyboard.KEY_DELETE, KEY_DELETE);

		// main keyboard misc
		add(org.lwjgl.input.Keyboard.KEY_ESCAPE, KEY_ESCAPE);
		add(org.lwjgl.input.Keyboard.KEY_GRAVE, KEY_GRAVE);
		add(org.lwjgl.input.Keyboard.KEY_MINUS, KEY_MINUS);
		add(org.lwjgl.input.Keyboard.KEY_EQUALS, KEY_EQUALS);
		add(org.lwjgl.input.Keyboard.KEY_BACK, KEY_BACK);
		add(org.lwjgl.input.Keyboard.KEY_TAB, KEY_TAB);
		add(org.lwjgl.input.Keyboard.KEY_LBRACKET, KEY_LBRACKET);
		add(org.lwjgl.input.Keyboard.KEY_RBRACKET, KEY_RBRACKET);
		add(org.lwjgl.input.Keyboard.KEY_RETURN, KEY_RETURN);
		add(org.lwjgl.input.Keyboard.KEY_SEMICOLON, KEY_SEMICOLON);
		add(org.lwjgl.input.Keyboard.KEY_APOSTROPHE, KEY_APOSTROPHE);
		add(org.lwjgl.input.Keyboard.KEY_BACKSLASH, KEY_BACKSLASH);
		add(org.lwjgl.input.Keyboard.KEY_COMMA, KEY_COMMA);
		add(org.lwjgl.input.Keyboard.KEY_PERIOD, KEY_PERIOD);
		add(org.lwjgl.input.Keyboard.KEY_SLASH, KEY_SLASH);
		add(org.lwjgl.input.Keyboard.KEY_SPACE, KEY_SPACE);
	}

	@Override
	public boolean isDown(int key) {
		return keys.contains(key);
	}

	public void update() {
		while (org.lwjgl.input.Keyboard.next()) {
			Integer theirKey = org.lwjgl.input.Keyboard.getEventKey();
			Integer ourKey = fromThem.get(theirKey);
			if (ourKey != null) {
				boolean isRepeat = org.lwjgl.input.Keyboard.isRepeatEvent();
				boolean suppress = isRepeat && nonRepeating(ourKey);
				if (!suppress) {
					boolean down = org.lwjgl.input.Keyboard.getEventKeyState();
					if (down) {
						keys.add(ourKey);
						queueEvent(ourKey, org.lwjgl.input.Keyboard.getEventCharacter());
					}
					else {
						keys.remove(ourKey);
						// we use ourKey here (which has the Locks merged)
						//
						// i'd like to track presses and releases of theirKey
						// (in a MultiCountingSet) then our KEY_SHIFT would be
						// down if either their shifts were down. However, theirKey
						// is borked for the various Lock keys ...
						// http://lwjgl.org/forum/index.php?msg=23104;topic=4268.0
						//
					}
				}
			}
		}
	}

	private boolean nonRepeating(int k) {
		return k>=KEYBEGIN_SHIFTS && k<=KEYEND_SHIFTS;
	}

	public void clear() {
		keys.clear();
	}

}
