package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.geom.Box;
import com.nney.utils.Math2;

public class IntegerProp extends SpecificProp<Integer> {
	private int ourMin;
	private int ourMax;

	public IntegerProp(PropPack pp) {
		super(pp);
		ourMin = pp.getAnn().min();
		ourMax = pp.getAnn().max();
	}

	@Override
	public void write(Integer n) {
		// n = Math2.limit(ourMin, ourMax, n);
		super.write(n);
	}

	@Override
	public String text() {
		return Integer.toString(read());
	}

	@Override
	public void writeText(String text) {
		try {
			write(Integer.parseInt(text));
		}
		catch (NumberFormatException e) {
			// ignored
		}
	}

	@Override
	public void getButtons(List<Button> buttons, final ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			public String name() {
				return "more";
			}

			@Override
			public void press() {
				write(read() + 1);
			}
		});
		buttons.add(new Button() {
			@Override
			public String name() {
				return "less";
			}

			@Override
			public void press() {
				write(read() - 1);
			}
		});
		addEditButton(buttons, bps);
	}

	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(Node d) {
		write(d.requireInt());
	}

	@Override
	public void validate(Box constraints) {
		write(Math2.limit(ourMin, ourMax, read()));
	}
}
