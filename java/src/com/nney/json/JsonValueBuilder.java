package com.nney.json;

import java.util.Stack;

public class JsonValueBuilder implements DataDestination {
	Stack<Builder> stack = new Stack<Builder>();
	
	DataItemImpl answer;
	
	@Override
	public void beginArray() {
		stack.add(new ArrayBuilder(new DataArray()));
	}

	@Override
	public void beginDict() {
		stack.add(new ObjectBuilder(new DataObject()));
	}

	@Override
	public void end() {
		add(stack.pop().value());
	}
	
	void add(DataItemImpl v) {
		if (stack.isEmpty()) {
			if (answer!=null) {
				throw new IllegalArgumentException("More than one top level item - array or object needed?");
			}
			answer = v;
		}
		else {
			stack.peek().take(v);
		}
	}

	@Override
	public void write(double value) {
		add(new DataDouble(value));
	}

	@Override
	public void write(int value) {
		add(new DataLong(value));
	}

	@Override
	public void write(long value) {
		add(new DataLong(value));
	}

	@Override
	public void write(boolean value) {
		add(new DataBoolean(value));
	}

	@Override
	public void write(String value) {
		add(new DataString(value));
	}

	@Override
	public void writeNull() {
		add(new DataNull());

	}

	public DataItemImpl result() {
		return answer;
	}
}
