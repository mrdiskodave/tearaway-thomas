package com.nney.datanode;

public abstract class NodeImpl implements Node {
	@Override
	public Node requireElement(int position) throws DataException {
		throw new DataException("array expected");
	}

	@Override
	public Node requireField(String name) throws DataException {
		throw new DataException("object expected");
	}

	@Override
	public double requireDouble() throws DataException {
		throw new DataException("double expected");
	}

	@Override
	public int requireInt() throws DataException {
		try {
			return (int) requireLong();
		}
		catch (DataException e) {
			throw new DataException("int expected");
		}
	}

	@Override
	public long requireLong() throws DataException {
		throw new DataException("long expected");
	}

	@Override
	public boolean requireBoolean() throws DataException {
		throw new DataException("boolean expected");
	}

	@Override
	public String requireString() throws DataException {
		throw new DataException("string expected");
	}

	@Override
	public boolean isNull() {
		return false;
	}

	@Override
	public boolean fieldExists(String fieldName) throws DataException {
		return false;
	}

	@Override
	public Node[] requireList() throws DataException {
		throw new DataException("array expected");
	}
}
