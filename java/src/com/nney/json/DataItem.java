package com.nney.json;

/**
 * An interface for getting at structured run-time type-checked data items.
 */
public interface DataItem {

	/**
	 * Assuming this item is an array, get an element from it.
	 * @param position Position in the array (where 0 is the first element).
	 * @return The item from the array.
	 * @throws DataException If the item is not an array or does not contain that many elements.
	 */
	DataItem requireElement(int position) throws DataException;


	/**
	 * Assuming this item is an array, get all the elements from it.
	 * 
	 * @return THe array content.
	 * @throws DataException If the item is not an array.
	 */
	DataItem[] requireList() throws DataException;

	
	/**
	 * Assuming this item is an object (AKA map AKA hash), get the named entry from it.
	 * @param fieldName The name of the field to get from the hash.
	 * @return The item stored under that key. 
	 * @throws DataException If the item is not an object or does not contain that named entry.
	 */
	DataItem requireField(String fieldName) throws DataException;

	/**
	 * Assuming this item is an object (AKA map AKA hash), check if it contains the named entry.
	 * @param fieldName The name of the field to check for.
	 * @return <code>true</code> if it exists and <code>false</code> otherwise.
	 * @throws DataException If the item is not an object.
	 */
	boolean fieldExists(String fieldName) throws DataException;

	// enquiry about plain old basic types follows
	// (they throw if type conversion is not possible and do not return null)
	
	double requireDouble() throws DataException;
	int requireInt() throws DataException;
	long requireLong() throws DataException;
	boolean requireBoolean() throws DataException;
	String requireString() throws DataException;

	boolean isNull();

}