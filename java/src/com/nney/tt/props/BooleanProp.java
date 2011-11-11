package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;

public class BooleanProp extends SpecificProp<Boolean> {
	private final String textTrue;
	private final String textFalse;

	public BooleanProp(PropPack pp) {
		super(pp);
		String t = "yes";
		String f = "no";
		if (pp.getAnn().xtraDef().equals("leftright")) {
			t = "left";
			f = "right";
		}
		textTrue = t;
		textFalse = f;
	}

	@Override
	public String text() {
		return read() ? textTrue : textFalse;
	}

	@Override
	public void getButtons(List<Button> buttons, ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			public String name() {
				return "change";
			}

			@Override
			public void press() {
				write(!read());
			}
		});
	}

	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(Node d) {
		write(d.requireBoolean());
	}
}
