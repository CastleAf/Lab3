package pt.tecnico.supplier.domain;

/**
 * Product entity. Only the product quantity is mutable so its get/set methods
 * are synchronized.
 */
public class Product {
	/** Product identifier. */
	private String productId;
	/** Product description. */
	private String description;
	/** Available quantity of product. */
	private volatile int quantity;
	/** Price of product */
	private int price;
	/** Is available */
	private boolean available;

	/** Create a new product */
	public Product(String pid, String description, int quantity, int price) {
		this.productId = pid;
		this.description = description;
		this.quantity = quantity;
		this.price = price;
		this.available = true;
	}

	public String getId() {
		return productId;
	}

	public String getDescription() {
		return description;
	}

	public int getPrice() {
		return price;
	}

	public boolean isAvailable() {
		return available;
	}

	public void setAvailable(boolean available) {
		this.available = available;
	}

	/** Synchronized locks object before returning quantity */
	public synchronized int getQuantity() {
		return quantity;
	}

	/** Synchronized locks object before setting quantity */
	public synchronized void setQuantity(int quantity) {
		this.quantity = quantity;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("Product [productId=").append(productId);
		builder.append(", description=").append(description);
		builder.append(", quantity=").append(quantity);
		builder.append(", price=").append(price);
		builder.append(", available=").append(available);
		builder.append("]");
		return builder.toString();
	}

}
