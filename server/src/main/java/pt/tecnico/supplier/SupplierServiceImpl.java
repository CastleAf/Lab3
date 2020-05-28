package pt.tecnico.supplier;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import com.google.protobuf.ByteString;
import com.google.type.Money;

import io.grpc.stub.StreamObserver;
import pt.tecnico.supplier.domain.Supplier;
import pt.tecnico.supplier.grpc.Product;
import pt.tecnico.supplier.grpc.ProductsRequest;
import pt.tecnico.supplier.grpc.ProductsResponse;
import pt.tecnico.supplier.grpc.SupplierGrpc;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import pt.tecnico.supplier.grpc.SignedResponse;
import pt.tecnico.supplier.grpc.Signature;

public class SupplierServiceImpl extends SupplierGrpc.SupplierImplBase {

	/**
	 * Set flag to true to print debug messages. The flag can be set using the
	 * -Ddebug command line option.
	 */
	private static final boolean DEBUG_FLAG = (System.getProperty("debug") != null);
	private static final String DIGEST_ALGO = "SHA-256";
	private static final String SYM_CIPHER = "AES/CBC/PKCS5Padding";

	/** Helper method to print debug messages. */
	private static void debug(String debugMessage) {
		if (DEBUG_FLAG)
			System.err.println(debugMessage);
	}

	/** Domain object. */
	final private Supplier supplier = Supplier.getInstance();

	/** Constructor */
	public SupplierServiceImpl() {
		debug("Loading demo data...");
		supplier.demoData();
	}

	/** Helper method to convert domain product to message product. */
	private Product buildProductFromProduct(pt.tecnico.supplier.domain.Product p) {
		Product.Builder productBuilder = Product.newBuilder();
		productBuilder.setIdentifier(p.getId());
		productBuilder.setDescription(p.getDescription());
		productBuilder.setQuantity(p.getQuantity());

		Money.Builder moneyBuilder = Money.newBuilder();
		moneyBuilder.setCurrencyCode("EUR").setUnits(p.getPrice());
		productBuilder.setPrice(moneyBuilder.build());

		return productBuilder.build();
	}

	@Override
	public void listProducts(ProductsRequest request, StreamObserver<SignedResponse> responseObserver) {
		debug("listProducts called");

		debug("Received request:");
		debug(request.toString());
		debug("in binary hexadecimals:");
		byte[] requestBinary = request.toByteArray();
		debug(String.format("%d bytes%n", requestBinary.length));

		// build response
		ProductsResponse.Builder responseBuilder = ProductsResponse.newBuilder();
		responseBuilder.setSupplierIdentifier(supplier.getId());
		for (String pid : supplier.getProductsIDs()) {
			pt.tecnico.supplier.domain.Product p = supplier.getProduct(pid);
			Product product = buildProductFromProduct(p);
			responseBuilder.addProduct(product);
		}
		ProductsResponse response = responseBuilder.build();

		debug("Response to send:");
		debug(response.toString());
		debug("in binary hexadecimals:");
		byte[] responseBinary = response.toByteArray();
		debug(printHexBinary(responseBinary));
		debug(String.format("%d bytes%n", responseBinary.length));

		SignedResponse.Builder aResponse = SignedResponse.newBuilder();
		aResponse.setResponse(response);


		// Digest and Cypher:
		byte[] iv = new byte[16];	// generate sample AES 16 byte initialization vector

		// let the system pick a strong secure random generator
		try {
			SecureRandom random = SecureRandom.getInstanceStrong();
			random.nextBytes(iv);
		}
		catch (java.security.NoSuchAlgorithmException e) {
			System.out.println("Didn't found that SecureRandom algorithm.");
		}

		// Read the secret key
		try {
			Key myKey = readKey("secret.key");


			// Generate Signature Value
			byte[] cypherDigest = digestAndCipher(responseBinary, myKey, iv);
			System.out.println("got here");
			ByteString myBytes = ByteString.copyFrom(cypherDigest);

			Signature.Builder signBuilder = Signature.newBuilder();
			signBuilder.setValue(myBytes);
			signBuilder.setSignerId("Server Id");            // FIXME: Used this because idk how to calc server id
			Signature mySignature = signBuilder.build();

			aResponse.setSignature(mySignature);
			SignedResponse myResponse = aResponse.build();
			System.out.println("Bruhhhh");

			// send single response back
			responseObserver.onNext(myResponse);
			// complete call
			responseObserver.onCompleted();
		} catch (java.lang.Exception e) {
			System.out.println("Error reading Secret Key.");
		}
	}

	public static Key readKey(String resourcePath) throws Exception {
		System.out.println("Reading key from resource " + resourcePath + " ...");

		InputStream fis = Thread.currentThread().getContextClassLoader().getResourceAsStream(resourcePath);
		byte[] encoded = new byte[fis.available()];
		fis.read(encoded);
		fis.close();

		System.out.println("Key:");
		System.out.println(printHexBinary(encoded));
		SecretKeySpec keySpec = new SecretKeySpec(encoded, "AES");

		return keySpec;
	}

	private static byte[] digestAndCipher(byte[] bytes, Key key, byte[] iv) throws Exception {

		// get a message digest object using the specified algorithm
		MessageDigest messageDigest = MessageDigest.getInstance(DIGEST_ALGO);

		// calculate the digest and print it out
		messageDigest.update(bytes);
		byte[] digest = messageDigest.digest();
		System.out.println("Digest:");
		System.out.println(printHexBinary(digest));

		// get an AES cipher object
		Cipher cipher = Cipher.getInstance(SYM_CIPHER);

		System.out.println("hre");
		IvParameterSpec ips = new IvParameterSpec(iv);
		// encrypt the plain text using the key
		cipher.init(Cipher.ENCRYPT_MODE, key, ips);
		byte[] cipherDigest = cipher.doFinal(digest);

		return cipherDigest;
	}

}
