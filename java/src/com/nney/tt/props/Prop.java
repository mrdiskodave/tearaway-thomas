package com.nney.tt.props;

import java.util.List;

import com.nney.json.DataDestination;
import com.nney.json.DataItem;
import com.nney.tt.geom.Coord;
import com.nney.tt.mapper.FieldAccessor;

public abstract class Prop {
	private PropPack pp;

	public Prop(PropPack pp) {
		this.pp = pp;
	}
	
	public FieldAccessor getFieldAccessor() {
		return pp.access();
	}
	
	public String name() {
		return pp.getAnn().name();
	}

	public String doc() {
		return pp.getAnn().doc();
	}

	public String label() {
		return pp.getAnn().label();
	}

	abstract public String text();
	
	public void copyFrom(Prop other) {
		pp.access().put(other.pp.access().getCopy());
	}

	public void validate() {
	}

	// ---------------------------------------------------------------------------
	// TEXT UI 
	
	public void getButtons(List<Button> buttons, ButtonPressServices bps) {
	}

	// ---------------------------------------------------------------------------
	// GRAPHICAL UI 

	public void getBats(List<Bat> bats) {
	}
	
	public void drawAuxBatStuff(VisualPropGC bt) {}

	public void moveBy(Coord delta) {
	}

	// ---------------------------------------------------------------------------
	// LOAD AND SAVE
	
	abstract void save(DataDestination d);
	abstract void load(DataItem d);
}
