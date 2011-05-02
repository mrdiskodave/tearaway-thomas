package com.nney.tt;

import java.util.LinkedList;
import java.util.ListIterator;

/**
 * A fridge is a one dimensional structure for freezing off screen objects.
 * 
 * <ul>
 * <li>Objects in a fridge are known to be off-screen.
 * <li>Objects in a fridge do not consume any processing resources.
 * <li>Objects in a fridge need only a single small test (performed in
 * {@link #remove(int)}) that establishes if <b>any</b> of them are coming back
 * on screen (in a constant time ... not related to the number of objects).
 * </ul>
 * 
 * <p>
 * The caller needs to maintain a fridge per screen edge.
 * 
 * <p>
 * The fridge has a position system where objects with numerically larger
 * positions are deeper in the fridge (i.e. further off-screen). Objects with
 * smaller positions are closer to returning to the screen. This means that,
 * when a screen edge is encountered as the ordinate increases, fridge position
 * is the same as screen ordinate. However, the fridge for the opposite screen
 * edge will need its given fridge positions negated by the caller.
 * 
 * @param <T>
 *            The type of the object - it need only support the interface
 *            {@link Fridge.Content}.
 */
public class Fridge<T extends Fridge.Content> {
	private LinkedList<T> content = new LinkedList<T>();
	private String name;

	/**
	 * The interface that all fridge content must support.
	 * 
	 */
	public interface Content {
		/**
		 * What is our fridge position?
		 * 
		 * @return The answer. See {@link Fridge} for a discussion of fridge
		 *         position.
		 */
		int getFridgePos();
	}

	public Fridge(String name) {
		this.name = name;
	}

	/**
	 * Add an object to this fridge at the given position.
	 * 
	 * @param item
	 *            The object to add.
	 * @param pos
	 *            The place to put it.
	 */
	public void add(T item, int pos) {
		System.out.println(String.format("Fridge: %08x(%7d) frozen    into %-6s", item.hashCode(), pos, name));
		// Skip (to the right) over existing items that should be to
		// the left of the one we've been given.
		ListIterator<T> ci = content.listIterator();
		while (ci.hasNext()) {
			if (ci.next().getFridgePos() >= pos) {
				ci.previous();
				break;
			}
		}
		// Insert it!
		ci.add(item);
	}

	/**
	 * Perhaps remove an object from this fridge.
	 * 
	 * @param left
	 *            Only remove the object if is left of (or on) this position.
	 * @return The object, if removed, or <code>null</code>.
	 */
	public T remove(int left) {
		T item = content.peekFirst();
		if (item == null || item.getFridgePos() > left) return null;
		System.out.println(String.format("Fridge: %08x(%7d) defrosted from %-6s using %d", item.hashCode(), item.getFridgePos(), name,
				left));
		assert item == content.removeFirst();
		return item;
	}
}
