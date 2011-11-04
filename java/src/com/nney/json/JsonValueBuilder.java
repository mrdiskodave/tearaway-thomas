package com.nney.json;

import java.util.Stack;

public class JsonValueBuilder implements DataDestination {
	Stack<Builder> stack = new Stack<Builder>();
	
	JsonValue answer;
	
	@Override
	public void beginArray() {
		stack.add(new ArrayBuilder(new JsonArray()));
	}

	@Override
	public void beginDict() {
		stack.add(new ObjectBuilder(new JsonObject()));
	}

	@Override
	public void end() {
		add(stack.pop().value());
	}
	
	void add(JsonValue v) {
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
		add(new JsonNumber(value));
	}

	@Override
	public void write(int value) {
		add(new JsonNumber(value));
	}

	@Override
	public void write(long value) {
		add(new JsonNumber(value));
	}

	@Override
	public void write(boolean value) {
		add(new JsonBoolean(value));
	}

	@Override
	public void write(String value) {
		add(new JsonString(value));
	}

	@Override
	public void writeNull() {
		add(new JsonNull());

	}

	public JsonValue result() {
		return answer;
	}
}
