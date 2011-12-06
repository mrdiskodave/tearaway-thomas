package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.List;

import com.nney.tt.SquareFridge;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.utils.ListUtil;

public class MapperAlienTracker {
	private SquareFridge<Alien> sf = new SquareFridge<Alien>();
	final private List<Alien> alienList = new ArrayList<Alien>();

	private void createFridge() {
		if (sf == null) {
			sf = new SquareFridge<Alien>();
		}
	}

	private void destroyFridge() {
		if (sf != null) {
			ListUtil.copy(alienList, sf);
			sf = null;
		}
	}

	public List<Alien> startDrawing(Box screenBox) {
		createFridge();
		sf.defrostAny(alienList, screenBox);
		return alienList;
	}

	public void endDrawing(Box screenBox) {
		createFridge();
		sf.freezeAny(alienList, screenBox);
	}

	public List<Alien> get() {
		destroyFridge();
		return alienList;
	}

	public void add(Alien alien) {
		alienList.add(alien);
	}
}
