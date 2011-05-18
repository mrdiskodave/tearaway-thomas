package com.nney.tt.lwjgl;

import org.lwjgl.input.Mouse;

import com.nney.tt.input.PartialPointerImpl;

public class LwjglPointer extends PartialPointerImpl {
	public void update() {
		// System.out.println(String.format("movements X%04d(%+04d),Y%04d(%+04d),W%04d l%.1S r%.1S w%.1S inside%.1S",
		// Mouse.getX(), Mouse.getDX(), Mouse.getY(), Mouse.getDY(),
		// Mouse.getDWheel(), Mouse.isButtonDown(0), Mouse.isButtonDown(1),
		// Mouse.isButtonDown(2), Mouse.isInsideWindow()));

		int x = Mouse.getX();
		int y = Mouse.getY();
		int w = Mouse.getDWheel();
		int b = 0;
		if (Mouse.isButtonDown(0)) b |= KEY_LEFT;
		if (Mouse.isButtonDown(1)) b |= KEY_RIGHT;
		if (Mouse.isButtonDown(2)) b |= KEY_MIDDLE;
		setNext(x, y, w, b);
	}

}
