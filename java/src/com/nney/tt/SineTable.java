package com.nney.tt;

public class SineTable {
	
	private int[] table;

	public SineTable(int size, int max) {
		table = new int[size];
		for (int idx=0; idx<size; idx++) {
			double angle = (2*Math.PI*size)/idx;
			table[idx] = (int) (Math.sin(angle)*size);
		}
	}
	
	public int read(int idx) {
		return table[idx%table.length];
	}

}
