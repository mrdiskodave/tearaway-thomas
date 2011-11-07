package com.nney.datanode;

public interface DataDestination {
	void beginArray();
	
	void beginObject();
	
	void end();
	
 	void write(double value); 

	void write(int value);

	void write(long value);

	void write(boolean value);

	void write(String value);
	
	void writeNull();
}
