package com.nney.tt.mapper;

import java.util.List;


public class PropDrawer {
	private int y;
	private final StatusLayer statusLayer;
	private final List<ButtonRecord> buttonRecords;
	private final HoverStatus hs;

	public PropDrawer(HoverStatus hs, StatusLayer statusLayer, List<ButtonRecord> buttonRecords) {
		this.hs = hs;
		this.statusLayer = statusLayer;
		this.buttonRecords = buttonRecords;
	}

	public void draw(Prop p) {
		statusLayer.draw(0, y, ButtonState.PASSIVE, clip(p.name(), 10));
		statusLayer.draw(10, y, ButtonState.PASSIVE, clip(p.text(), 20));

		String[] buttons = p.createButtons();
		if (buttons != null) {
			int x = 30;
			for (int b = 0; b < buttons.length; b++) {
				String buttonText = "[" + buttons[b] + "]";
				ButtonRecord br = new ButtonRecord(p, b, statusLayer.getBox(x, y, buttonText));
				buttonRecords.add(br);
				statusLayer.draw(x, y, hs.status(br.getUniqueName()), buttonText);
				x += buttonText.length() + 1;
			}
		}
		y++;
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

}
