package com.nney.tt.mapper;

import java.util.List;

public class PropDrawer {
	private int y;
	private final StatusLayer statusLayer;
	private final List<ButtonRecord> buttonRecords;

	public PropDrawer(StatusLayer statusLayer, List<ButtonRecord> buttonRecords) {
		this.statusLayer = statusLayer;
		this.buttonRecords = buttonRecords;
	}

	public void draw(Prop p) {
		statusLayer.draw(0, y, 0xffffffff, clip(p.name(), 10));
		statusLayer.draw(10, y, 0xffffffff, clip(p.text(), 20));

		String[] buttons = p.createButtons();
		if (buttons != null) {
			int x = 30;
			for (int b = 0; b < buttons.length; b++) {
				String buttonText = "[" + buttons[b] + "]";
				int col = p.isDown() ? 0xffff0000 : 0xffffffff;
				System.out.println(String.format("col=%x", col));
				buttonRecords.add(new ButtonRecord(p, b, statusLayer.draw(x, y, col, buttonText)));
				x += buttonText.length() + 1;
			}
		}
		y++;
	}

	private static String clip(String s, int x) {
		return s.substring(0, Math.min(x, s.length()));
	}

}
