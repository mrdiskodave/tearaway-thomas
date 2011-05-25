package com.nney.tt.mapper;


public class PropDrawer {
	private int y;
	private final StatusLayer statusLayer;
	private final CollidableList<ButtonRecord> buttonRecords;
	private final HoverStatus hs;
	private final ButtonPressServices bps;

	public PropDrawer(ButtonPressServices bps, HoverStatus hs, StatusLayer statusLayer, CollidableList<ButtonRecord> buttons) {
		this.bps = bps;
		this.hs = hs;
		this.statusLayer = statusLayer;
		this.buttonRecords = buttons;
	}

	public void draw(final Prop p) {
		statusLayer.draw(0, y, ButtonState.PASSIVE, clip(p.name(), 10));
		statusLayer.draw(10, y, ButtonState.PASSIVE, clip(p.text(), 20));

		String[] buttons = p.getButtons();
		if (buttons != null) {
			int x = 30;
			for (int b = 0; b < buttons.length; b++) {
				String buttonText = "[" + buttons[b] + "]";
				final int bb = b;
				ButtonRecord br = new ButtonRecord(bb, p, bps, statusLayer.getBox(x, y, buttonText));
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
