package com.nney.tt.mapper;

import java.util.ArrayList;

import com.nney.tt.geom.Box;

public class PropDrawer {
	private int y;
	private final StatusLayer statusLayer;
	private final CollidableList<ButtonRecord> buttonRecords;
	private final HoverStatus hs;
	private final ButtonPressServices bps;

	public PropDrawer(ButtonPressServices bps, HoverStatus hs, StatusLayer statusLayer,
			CollidableList<ButtonRecord> buttons) {
		this.bps = bps;
		this.hs = hs;
		this.statusLayer = statusLayer;
		this.buttonRecords = buttons;
	}

	public void draw(final Prop p) {
		statusLayer.draw(0, y, ButtonState.PASSIVE, clip(p.name(), 10));
		statusLayer.draw(10, y, ButtonState.PASSIVE, clip(p.text(), 20));

		ArrayList<Button> buttons = new ArrayList<Button>();
		p.getButtons(buttons, bps);
		int x = 35;
		for (Button button: buttons) {
			String buttonText = "[" + button.name() + "]";
			Box buttonBox = statusLayer.getBox(x, y, buttonText);
//			System.out.println(buttonText+" "+buttonBox);
			ButtonRecord br = new ButtonRecord(button, buttonBox);
			buttonRecords.add(br);
			statusLayer.draw(x, y, hs.status(br.getUniqueName()), buttonText);
			x += buttonText.length() + 1;
		}
		y++;
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

}
