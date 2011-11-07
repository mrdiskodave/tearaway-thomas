package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;

public class IntegerProp extends SpecificProp<Integer> {
	public IntegerProp(PropPack pp) {
		super(pp);
	}

	@Override
	public String text() {
		return Integer.toString(read());
	}
	
	@Override
	public void getButtons(List<Button> buttons, ButtonPressServices bps) {
		buttons.add(new Button() {
			@Override
			public String name() {
				return "more";
			}

			@Override
			public void press() {
				write(read()+1);
			}
		});
		buttons.add(new Button() {
			@Override
			public String name() {
				return "less";
			}

			@Override
			public void press() {
				write(read()-1);
			}
		});
	}
	
	@Override
	void save(DataDestination d) {
		d.write(read());
	}

	@Override
	void load(Node d) {
		write(d.requireInt());
	}
}
