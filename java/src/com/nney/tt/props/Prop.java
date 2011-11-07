package com.nney.tt.props;

import java.util.List;

import com.nney.datanode.DataDestination;
import com.nney.datanode.Node;
import com.nney.tt.geom.Coord;
import com.nney.tt.mapper.FieldAccessor;

/**
 * Meta information and operations on an object property (AKA an object field). 
 */
public abstract class Prop {
	private PropPack pp;

	public Prop(PropPack pp) {
		this.pp = pp;
	}
	
	public FieldAccessor getFieldAccessor() {
		return pp.access();
	}
	
	public String name() {
		return pp.name();
	}

	public String doc() {
		return pp.getAnn().doc();
	}

	public String label() {
		return pp.label();
	}
	
	public void copyFrom(Prop other) {
		getFieldAccessor().put(other.getFieldAccessor().getCopy());
	}

	public void validate() {
	}

	// ---------------------------------------------------------------------------
	// TEXT UI 

	abstract public String text();
	
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
	abstract void load(Node d);
}
