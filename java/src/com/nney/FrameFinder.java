package com.nney;

import java.util.ArrayList;
import java.util.List;

public class FrameFinder {
	//
	// ---------------------------------------------
	// state
	//
	//

	String file;
	int pos;

	public void move(int distance) {
		pos += distance;
	}

	public void setFile(String name) {
		file = name;
		pos = 0;
	}

	public List<Frame> next(int number) {
		List<Frame> answer = new ArrayList<Frame>();
		for (int x = 0; x < number; x++) {
			answer.add(new Frame(file, pos));
			pos++;
		}
		return answer;
	}
	
	public List<Frame> next() {
		return next(1);
	}

	public List<Frame> cycle(int length) {
		assert length > 2;
		List<Frame> answer = next(length);
		// back (need not repeat start or end of cycle)
		int p = answer.size() - 2;
		for (int x = 0; x < length - 2; x++) {
			answer.add(answer.get(p - x));
		}
		return answer;
	}
}
