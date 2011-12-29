package com.nney.tt.mapper;

public class HoverStatus<T> {
	private T hover;
	private T pressed;

	private void neverNone(T name) {
		assert name != null;
	}

	public void move(T name) {
		hover = name;
	}

	public void down(T name) {
		neverNone(name);
		pressed = name;
	}

	public boolean up(T name) {
		boolean activation = name != null && status(name) == ButtonState.PRESSED;
		pressed = null;
		return activation;
	}

	public ButtonState status(T name) {
		neverNone(name);
		return status0(name);
	}

	private ButtonState status0(T name) {
		boolean isHoveringOverUs = name.equals(hover);
		boolean isPressedOnUs = name.equals(pressed);

		if (isHoveringOverUs) {
			if (isPressedOnUs) {
				return ButtonState.PRESSED;
			}
			else {
				boolean isPressedOnSomethingElse = pressed != null;
				if (isPressedOnSomethingElse) {
					return ButtonState.PASSIVE;
				}
				else {
					return ButtonState.HOVER;
				}
			}
		}
		else {
			if (isPressedOnUs) {
				return ButtonState.HOVER;
			}
			else {
				return ButtonState.PASSIVE;
			}
		}
	}
}
