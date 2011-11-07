package com.nney.datanode;

import java.util.Stack;


public class NodeDataDestination implements DataDestination {
	Stack<Builder> stack = new Stack<Builder>();
	
	Node answer;
	
	@Override
	public void beginArray() {
		stack.add(new ArrayBuilder(new ArrayNode()));
	}

	@Override
	public void beginObject() {
		stack.add(new ObjectBuilder(new ObjectNode()));
	}

	@Override
	public void end() {
		add(stack.pop().value());
	}
	
	void add(Node v) {
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
		add(new DoubleNode(value));
	}

	@Override
	public void write(int value) {
		add(new LongNode(value));
	}

	@Override
	public void write(long value) {
		add(new LongNode(value));
	}

	@Override
	public void write(boolean value) {
		add(new BooleanNode(value));
	}

	@Override
	public void write(String value) {
		add(new StringNode(value));
	}

	@Override
	public void writeNull() {
		add(new NullNode());

	}

	public Node result() {
		return answer;
	}
}
