package com.nney.tt.mapper;

public class HoverStatus {
	private String hover = "";
	private String pressed = "";

	public void move(String name) {
		maybeNone(name);
		hover = name;
	}
	
	public void down(String name) {
		neverNone(name);
		pressed = name;
	}
	
	public boolean up(String name) {
		maybeNone(name);
		boolean activation = status(name)==ButtonState.PRESSED;
		pressed = "";
		return activation && isNotNone(name);
	}

	public ButtonState status(String name) {
		maybeNone(name);
		return status0(name);
	}

	private void maybeNone(String name) {
		assert name!=null;
	}

	private void neverNone(String name) {
		assert name!=null;
		assert isNotNone(name);
	}

	private boolean isNotNone(String name) {
		return name.length()>0;
	}

	private ButtonState status0(String name) {
		boolean isHoveringOverUs = name.equals(hover);
		boolean isPressedOnUs = name.equals(pressed);

		if (isHoveringOverUs) {
			if (isPressedOnUs) {
				return ButtonState.PRESSED;
			}
			else {
				boolean isPressedOnSomethingElse = isNotNone(pressed);
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
