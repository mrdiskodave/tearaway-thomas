package com.nney.tt;

import java.util.Iterator;
import java.util.LinkedList;
import java.util.ListIterator;

import com.nney.utils.ReadOnlyIterator;

/**
 * A fridge is a one dimensional structure for freezing out-of-bounds objects
 * (with {@link #add(Object, int)}). As the bounds change you can discover if
 * any object is coming back into bounds in constant time using
 * {@link #pop(int)}.
 * 
 * <p>
 * The fridge has a position system where objects with numerically larger
 * positions are deeper in the fridge (i.e. further out of bounds). Objects with
 * smaller positions are closer to returning into bounds. The caller needs to
 * keep two fridges - one per bounds dimension.
 * 
 * <p>
 * For example, if the bounds were a 2D view onto a larger 2D playing area then
 * you'd have four fridges (north, south, west, east). If an active object
 * leaves the screen to the south then <code>add()</code> it to the southern
 * fridge (giving it's the y-ordinate of its top as the parameter "pos") then
 * forget about it. As the screen scrolls you can check if <b>any</b> of the
 * objects frozen to the south of the screen are coming back into view by
 * calling southFridge.pop() passing with the y-ordinate of the bottom of the
 * screen as the parameter "edge". An object popped from the southFridge may be
 * off-screen on another ordinate (e.g. to the west or east). If this is the
 * case then simply add() the object to that fridge and forget it again. If that
 * isn't the case then that object is back in play. Coordinates won't be
 * increasing to the north south and to the west and east. Depending on your
 * coordinate system the decreasing ordinate will need to be negated to fit with
 * the fridge's "bigger ordinate means further out of bounds" ordinate system.
 * 
 * <p>
 * Frozen objects can be forgotten about - and use no CPU cycles - until pop()
 * revives them.
 * 
 * @param <T>
 *            The type of the object we hold.
 */
public class Fridge<T> implements Iterable<T> {
	private LinkedList<FridgeEntry> content = new LinkedList<>();

	@SuppressWarnings("unused")
	// it is for debug output
	private String name;

	class FridgeEntry {
		final T item;
		final int pos;

		FridgeEntry(T item, int pos) {
			this.item = item;
			this.pos = pos;
		}
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
		// System.out.println(String.format("Fridge: %08x(%7d) frozen    into %-6s",
		// item.hashCode(), pos, name));

		// Insert the item so the Fridge remains sorted by pos
		ListIterator<FridgeEntry> ci = content.listIterator();
		while (ci.hasNext()) {
			if (ci.next().pos >= pos) {
				ci.previous();
				break;
			}
		}
		// Insert it!
		ci.add(new FridgeEntry(item, pos));
	}

	/**
	 * Perhaps remove an object from this fridge. Call this repeatedly until it
	 * returns <code>null</code>.
	 * 
	 * @param edge
	 *            Only remove the object if it's position is <= edge
	 * @return The object, if removed, or <code>null</code>.
	 */
	public T pop(int edge) {
		FridgeEntry fe = content.peekFirst();
		if (fe == null || fe.pos > edge) return null;
		// System.out.println(String.format("Fridge: %08x(%7d) defrosted from %-6s using %d",
		// fe.item.hashCode(), fe.pos, name, edge));
		content.removeFirst();
		return fe.item;
	}

	/**
	 * Iterate through fridge content.
	 * 
	 * @return The requested iterator.
	 */
	@Override
	public Iterator<T> iterator() {
		final Iterator<FridgeEntry> it = content.iterator();
		return new ReadOnlyIterator<>() {
			@Override
			public boolean hasNext() {
				return it.hasNext();
			}

			@Override
			public T next() {
				return it.next().item;
			}
		};
	}
}
