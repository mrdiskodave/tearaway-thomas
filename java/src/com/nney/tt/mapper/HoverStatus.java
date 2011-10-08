package com.nney.tt.mapper;

public class HoverStatus {
	private String hover;
	private String pressed;

	
	private void maybeNone(String name) {
		assert name==null || name.length()>0;
	}

	private void neverNone(String name) {
		assert name!=null && name.length()>0;
	}

	
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
		boolean activation = name!=null && status(name)==ButtonState.PRESSED;
		pressed = null;
		return activation;
	}

	public ButtonState status(String name) {
		neverNone(name);
		return status0(name);
	}

	private ButtonState status0(String name) {
		boolean isHoveringOverUs = name.equals(hover);
		boolean isPressedOnUs = name.equals(pressed);

		if (isHoveringOverUs) {
			if (isPressedOnUs) {
				return ButtonState.PRESSED;
			}
			else {
				boolean isPressedOnSomethingElse = pressed!=null;
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
