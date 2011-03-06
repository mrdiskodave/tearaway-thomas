package com.nney;

import java.util.ArrayList;
import java.util.List;

/**
 * A short-hand way of finding (i.e. naming) ranges and cycles of {@link Frame}s.
 */
public class FrameFinder {
	// our internal state ... very much like the two final fields in a Frame
	private String name;
	private int number;

	public void move(int distance) {
		number += distance;
	}

	public void selectInput(String name) {
		this.name = name;
		number = 0;
	}

	public List<Frame> next(int howMany) {
		List<Frame> answer = new ArrayList<Frame>();
		do {
			answer.add(new Frame(name, number));
			number++;
		} while (--howMany>0);
		return answer;
	}
	
	public List<Frame> cycle(int length) {
		assert length > 2;
		// forward
		List<Frame> answer = next(length);
		// and back (need not repeat start or end of cycle)
		int p = answer.size() - 2;
		for (int x = 0; x < length - 2; x++) {
			answer.add(answer.get(p - x));
		}
		return answer;
	}
}
