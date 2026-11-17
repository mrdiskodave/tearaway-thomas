package com.nney.tt.mapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.nney.tt.ConcatenatedIterator;
import com.nney.tt.SquareFridge;
import com.nney.tt.aliens.Alien;
import com.nney.tt.geom.Box;
import com.nney.utils.ListUtil;

public class MapperAlienTracker implements Iterable<Alien> {
	private SquareFridge<Alien> squareFridge = new SquareFridge<>();
	final private List<Alien> alienList = new ArrayList<>();

	private void createFridge() {
		if (squareFridge == null) {
			System.out.println("create fridge");
			squareFridge = new SquareFridge<>();
		}
	}

	private void destroyFridge() {
		if (squareFridge != null) {
			System.out.println("destroy fridge");
			ListUtil.copy(alienList, squareFridge);
			squareFridge = null;
		}
	}

	public List<Alien> startDrawing(Box screenBox) {
		createFridge();
		squareFridge.defrostAny(alienList, screenBox);
		return alienList;
	}

	public void endDrawing(Box screenBox) {
		createFridge();
		squareFridge.freezeAny(alienList, screenBox);
	}

	public List<Alien> get() {
		destroyFridge();
		return alienList;
	}

	public void add(Alien alien) {
		alienList.add(alien);
	}

	@Override
	public Iterator<Alien> iterator() {
		ConcatenatedIterator<Alien> ci = new ConcatenatedIterator<>();
		ci.add(squareFridge);
		ci.add(alienList);
		return ci;
	}
}
