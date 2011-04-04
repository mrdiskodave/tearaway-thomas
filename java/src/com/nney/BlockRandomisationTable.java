package com.nney;

import java.util.ArrayList;
import java.util.Random;
import java.util.TreeMap;

import com.nney.json.DataException;
import com.nney.json.DataItem;

public class BlockRandomisationTable {
	private final TreeMap<Integer, ArrayList<Integer>> tm = new TreeMap<Integer, ArrayList<Integer>>();
	
	private final Random r = new Random();
	
	public void load(DataItem di) throws DataException {
		for (DataItem line: di.requireList()) {
			ArrayList<Integer> al = new ArrayList<Integer>();
			for (DataItem x: line.requireList()) {
				al.add(x.requireInt());
			}
			for (int x: al) {
				assert !tm.containsKey(x);
				tm.put(x, al);
			}
		}
	}

	public boolean needsShuffle(int block) {
		return tm.containsKey(block);
	}
	
	public int shuffle(int block) {
		ArrayList<Integer> a = tm.get(block);
		return a.get(r.nextInt(a.size()));
	}

}
