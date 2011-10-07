package com.nney.tt.mapper;

public class HoverStatus {
	private String hover = "";
	private String pressed = "";

	public void move(String name) {
		assert name!=null;
		hover = name;
	}
	
	public void down(String name) {
		assert name!=null;
		pressed = name;
	}
	
	public boolean up(String name) {
		assert name!=null;
		boolean activation = status(name)==ButtonState.PRESSED;
		pressed = "";
		return activation && name.length()>0;
	}

	public ButtonState status(String name) {
		return status0(name);
	}

	private ButtonState status0(String name) {
		assert name!=null;
		boolean isHoveringOverUs = name.equals(hover);
		boolean isPressedOnUs = name.equals(pressed);

		if (isHoveringOverUs) {
			if (isPressedOnUs) {
				return ButtonState.PRESSED;
			}
			else {
				boolean isPressedOnSomethingElse = pressed.length()>0;
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
