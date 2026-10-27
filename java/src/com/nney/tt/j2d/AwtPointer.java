package com.nney.tt.j2d;

import java.awt.AWTException;
import java.awt.Component;
import java.awt.Point;
import java.awt.Robot;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;

import com.nney.tt.input.PartialPointerImpl;

/**
 * Mouse input from AWT, translated into game-screen coordinates (0..399,
 * 0..299) whatever size the window is. Used by the map editor.
 */
public class AwtPointer extends PartialPointerImpl {
	/** Converts between window pixels and game pixels. */
	public interface Mapping {
		Point toGame(int wx, int wy);

		Point toWindow(int gx, int gy);
	}

	private final Component component;
	private final Mapping mapping;

	private volatile int wx;
	private volatile int wy;
	private volatile int buttons;
	private volatile int wheel;

	public AwtPointer(Component component, Mapping mapping) {
		this.component = component;
		this.mapping = mapping;
		MouseAdapter ma = new MouseAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				wx = e.getX();
				wy = e.getY();
			}

			@Override
			public void mouseDragged(MouseEvent e) {
				mouseMoved(e);
			}

			@Override
			public void mousePressed(MouseEvent e) {
				mouseMoved(e);
				buttons |= bit(e);
			}

			@Override
			public void mouseReleased(MouseEvent e) {
				mouseMoved(e);
				buttons &= ~bit(e);
			}

			@Override
			public void mouseWheelMoved(MouseWheelEvent e) {
				// LWJGL: positive is "away from the user"
				synchronized (AwtPointer.this) {
					wheel -= e.getWheelRotation();
				}
			}
		};
		component.addMouseListener(ma);
		component.addMouseMotionListener(ma);
		component.addMouseWheelListener(ma);
	}

	private static int bit(MouseEvent e) {
		switch (e.getButton()) {
		case MouseEvent.BUTTON1:
			return 1;
		case MouseEvent.BUTTON3:
			return 2;
		case MouseEvent.BUTTON2:
			return 4;
		default:
			return 0;
		}
	}

	/** Once a frame, on the game thread. */
	public void update() {
		int w;
		synchronized (this) {
			w = wheel;
			wheel = 0;
		}
		Point p = mapping.toGame(wx, wy);
		setNext(p.x, p.y, w, buttons);
	}

	@Override
	public void set(int x, int y) {
		try {
			Point p = mapping.toWindow(x, y);
			Point origin = component.getLocationOnScreen();
			new Robot().mouseMove(origin.x + p.x, origin.y + p.y);
			wx = p.x;
			wy = p.y;
		}
		catch (AWTException e) {
			// can't move the mouse on this platform; not important
		}
		catch (RuntimeException e) {
			// component not showing yet
		}
	}
}
