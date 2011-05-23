package com.nney.tt.mapper;

public class ButtonAction {
	private final Prop who;
	private final int what;

	public ButtonAction(Prop who, int what) {
		this.who = who;
		this.what = what;
	}
	
	public void takeAction(ButtonPressServices srv) {
		who.onButtonPress(what, srv);
	}
}
