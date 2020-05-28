// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: supplier.proto

package pt.tecnico.supplier.grpc;

/**
 * <pre>
 * product information
 * </pre>
 *
 * Protobuf type {@code pt.tecnico.supplier.grpc.Product}
 */
public  final class Product extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:pt.tecnico.supplier.grpc.Product)
    ProductOrBuilder {
private static final long serialVersionUID = 0L;
  // Use Product.newBuilder() to construct.
  private Product(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private Product() {
    identifier_ = "";
    description_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new Product();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private Product(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    this();
    if (extensionRegistry == null) {
      throw new java.lang.NullPointerException();
    }
    com.google.protobuf.UnknownFieldSet.Builder unknownFields =
        com.google.protobuf.UnknownFieldSet.newBuilder();
    try {
      boolean done = false;
      while (!done) {
        int tag = input.readTag();
        switch (tag) {
          case 0:
            done = true;
            break;
          case 10: {
            java.lang.String s = input.readStringRequireUtf8();

            identifier_ = s;
            break;
          }
          case 18: {
            java.lang.String s = input.readStringRequireUtf8();

            description_ = s;
            break;
          }
          case 24: {

            quantity_ = input.readInt32();
            break;
          }
          case 34: {
            com.google.type.Money.Builder subBuilder = null;
            if (price_ != null) {
              subBuilder = price_.toBuilder();
            }
            price_ = input.readMessage(com.google.type.Money.parser(), extensionRegistry);
            if (subBuilder != null) {
              subBuilder.mergeFrom(price_);
              price_ = subBuilder.buildPartial();
            }

            break;
          }
          case 40: {

            available_ = input.readBool();
            break;
          }
          default: {
            if (!parseUnknownField(
                input, unknownFields, extensionRegistry, tag)) {
              done = true;
            }
            break;
          }
        }
      }
    } catch (com.google.protobuf.InvalidProtocolBufferException e) {
      throw e.setUnfinishedMessage(this);
    } catch (java.io.IOException e) {
      throw new com.google.protobuf.InvalidProtocolBufferException(
          e).setUnfinishedMessage(this);
    } finally {
      this.unknownFields = unknownFields.build();
      makeExtensionsImmutable();
    }
  }
  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Product_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Product_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            pt.tecnico.supplier.grpc.Product.class, pt.tecnico.supplier.grpc.Product.Builder.class);
  }

  public static final int IDENTIFIER_FIELD_NUMBER = 1;
  private volatile java.lang.Object identifier_;
  /**
   * <code>string identifier = 1;</code>
   * @return The identifier.
   */
  public java.lang.String getIdentifier() {
    java.lang.Object ref = identifier_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      identifier_ = s;
      return s;
    }
  }
  /**
   * <code>string identifier = 1;</code>
   * @return The bytes for identifier.
   */
  public com.google.protobuf.ByteString
      getIdentifierBytes() {
    java.lang.Object ref = identifier_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      identifier_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int DESCRIPTION_FIELD_NUMBER = 2;
  private volatile java.lang.Object description_;
  /**
   * <code>string description = 2;</code>
   * @return The description.
   */
  public java.lang.String getDescription() {
    java.lang.Object ref = description_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      description_ = s;
      return s;
    }
  }
  /**
   * <code>string description = 2;</code>
   * @return The bytes for description.
   */
  public com.google.protobuf.ByteString
      getDescriptionBytes() {
    java.lang.Object ref = description_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      description_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int QUANTITY_FIELD_NUMBER = 3;
  private int quantity_;
  /**
   * <code>int32 quantity = 3;</code>
   * @return The quantity.
   */
  public int getQuantity() {
    return quantity_;
  }

  public static final int PRICE_FIELD_NUMBER = 4;
  private com.google.type.Money price_;
  /**
   * <code>.google.type.Money price = 4;</code>
   * @return Whether the price field is set.
   */
  public boolean hasPrice() {
    return price_ != null;
  }
  /**
   * <code>.google.type.Money price = 4;</code>
   * @return The price.
   */
  public com.google.type.Money getPrice() {
    return price_ == null ? com.google.type.Money.getDefaultInstance() : price_;
  }
  /**
   * <code>.google.type.Money price = 4;</code>
   */
  public com.google.type.MoneyOrBuilder getPriceOrBuilder() {
    return getPrice();
  }

  public static final int AVAILABLE_FIELD_NUMBER = 5;
  private boolean available_;
  /**
   * <code>bool available = 5;</code>
   * @return The available.
   */
  public boolean getAvailable() {
    return available_;
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (!getIdentifierBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, identifier_);
    }
    if (!getDescriptionBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, description_);
    }
    if (quantity_ != 0) {
      output.writeInt32(3, quantity_);
    }
    if (price_ != null) {
      output.writeMessage(4, getPrice());
    }
    if (available_ != false) {
      output.writeBool(5, available_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getIdentifierBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, identifier_);
    }
    if (!getDescriptionBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, description_);
    }
    if (quantity_ != 0) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt32Size(3, quantity_);
    }
    if (price_ != null) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(4, getPrice());
    }
    if (available_ != false) {
      size += com.google.protobuf.CodedOutputStream
        .computeBoolSize(5, available_);
    }
    size += unknownFields.getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof pt.tecnico.supplier.grpc.Product)) {
      return super.equals(obj);
    }
    pt.tecnico.supplier.grpc.Product other = (pt.tecnico.supplier.grpc.Product) obj;

    if (!getIdentifier()
        .equals(other.getIdentifier())) return false;
    if (!getDescription()
        .equals(other.getDescription())) return false;
    if (getQuantity()
        != other.getQuantity()) return false;
    if (hasPrice() != other.hasPrice()) return false;
    if (hasPrice()) {
      if (!getPrice()
          .equals(other.getPrice())) return false;
    }
    if (getAvailable()
        != other.getAvailable()) return false;
    if (!unknownFields.equals(other.unknownFields)) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    hash = (37 * hash) + IDENTIFIER_FIELD_NUMBER;
    hash = (53 * hash) + getIdentifier().hashCode();
    hash = (37 * hash) + DESCRIPTION_FIELD_NUMBER;
    hash = (53 * hash) + getDescription().hashCode();
    hash = (37 * hash) + QUANTITY_FIELD_NUMBER;
    hash = (53 * hash) + getQuantity();
    if (hasPrice()) {
      hash = (37 * hash) + PRICE_FIELD_NUMBER;
      hash = (53 * hash) + getPrice().hashCode();
    }
    hash = (37 * hash) + AVAILABLE_FIELD_NUMBER;
    hash = (53 * hash) + com.google.protobuf.Internal.hashBoolean(
        getAvailable());
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static pt.tecnico.supplier.grpc.Product parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Product parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Product parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Product parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(pt.tecnico.supplier.grpc.Product prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * <pre>
   * product information
   * </pre>
   *
   * Protobuf type {@code pt.tecnico.supplier.grpc.Product}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:pt.tecnico.supplier.grpc.Product)
      pt.tecnico.supplier.grpc.ProductOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Product_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Product_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              pt.tecnico.supplier.grpc.Product.class, pt.tecnico.supplier.grpc.Product.Builder.class);
    }

    // Construct using pt.tecnico.supplier.grpc.Product.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      identifier_ = "";

      description_ = "";

      quantity_ = 0;

      if (priceBuilder_ == null) {
        price_ = null;
      } else {
        price_ = null;
        priceBuilder_ = null;
      }
      available_ = false;

      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Product_descriptor;
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Product getDefaultInstanceForType() {
      return pt.tecnico.supplier.grpc.Product.getDefaultInstance();
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Product build() {
      pt.tecnico.supplier.grpc.Product result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Product buildPartial() {
      pt.tecnico.supplier.grpc.Product result = new pt.tecnico.supplier.grpc.Product(this);
      result.identifier_ = identifier_;
      result.description_ = description_;
      result.quantity_ = quantity_;
      if (priceBuilder_ == null) {
        result.price_ = price_;
      } else {
        result.price_ = priceBuilder_.build();
      }
      result.available_ = available_;
      onBuilt();
      return result;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof pt.tecnico.supplier.grpc.Product) {
        return mergeFrom((pt.tecnico.supplier.grpc.Product)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(pt.tecnico.supplier.grpc.Product other) {
      if (other == pt.tecnico.supplier.grpc.Product.getDefaultInstance()) return this;
      if (!other.getIdentifier().isEmpty()) {
        identifier_ = other.identifier_;
        onChanged();
      }
      if (!other.getDescription().isEmpty()) {
        description_ = other.description_;
        onChanged();
      }
      if (other.getQuantity() != 0) {
        setQuantity(other.getQuantity());
      }
      if (other.hasPrice()) {
        mergePrice(other.getPrice());
      }
      if (other.getAvailable() != false) {
        setAvailable(other.getAvailable());
      }
      this.mergeUnknownFields(other.unknownFields);
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      pt.tecnico.supplier.grpc.Product parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (pt.tecnico.supplier.grpc.Product) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private java.lang.Object identifier_ = "";
    /**
     * <code>string identifier = 1;</code>
     * @return The identifier.
     */
    public java.lang.String getIdentifier() {
      java.lang.Object ref = identifier_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        identifier_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string identifier = 1;</code>
     * @return The bytes for identifier.
     */
    public com.google.protobuf.ByteString
        getIdentifierBytes() {
      java.lang.Object ref = identifier_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        identifier_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string identifier = 1;</code>
     * @param value The identifier to set.
     * @return This builder for chaining.
     */
    public Builder setIdentifier(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      identifier_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string identifier = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearIdentifier() {
      
      identifier_ = getDefaultInstance().getIdentifier();
      onChanged();
      return this;
    }
    /**
     * <code>string identifier = 1;</code>
     * @param value The bytes for identifier to set.
     * @return This builder for chaining.
     */
    public Builder setIdentifierBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      identifier_ = value;
      onChanged();
      return this;
    }

    private java.lang.Object description_ = "";
    /**
     * <code>string description = 2;</code>
     * @return The description.
     */
    public java.lang.String getDescription() {
      java.lang.Object ref = description_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        description_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string description = 2;</code>
     * @return The bytes for description.
     */
    public com.google.protobuf.ByteString
        getDescriptionBytes() {
      java.lang.Object ref = description_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        description_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string description = 2;</code>
     * @param value The description to set.
     * @return This builder for chaining.
     */
    public Builder setDescription(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      description_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string description = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearDescription() {
      
      description_ = getDefaultInstance().getDescription();
      onChanged();
      return this;
    }
    /**
     * <code>string description = 2;</code>
     * @param value The bytes for description to set.
     * @return This builder for chaining.
     */
    public Builder setDescriptionBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      description_ = value;
      onChanged();
      return this;
    }

    private int quantity_ ;
    /**
     * <code>int32 quantity = 3;</code>
     * @return The quantity.
     */
    public int getQuantity() {
      return quantity_;
    }
    /**
     * <code>int32 quantity = 3;</code>
     * @param value The quantity to set.
     * @return This builder for chaining.
     */
    public Builder setQuantity(int value) {
      
      quantity_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>int32 quantity = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearQuantity() {
      
      quantity_ = 0;
      onChanged();
      return this;
    }

    private com.google.type.Money price_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.google.type.Money, com.google.type.Money.Builder, com.google.type.MoneyOrBuilder> priceBuilder_;
    /**
     * <code>.google.type.Money price = 4;</code>
     * @return Whether the price field is set.
     */
    public boolean hasPrice() {
      return priceBuilder_ != null || price_ != null;
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     * @return The price.
     */
    public com.google.type.Money getPrice() {
      if (priceBuilder_ == null) {
        return price_ == null ? com.google.type.Money.getDefaultInstance() : price_;
      } else {
        return priceBuilder_.getMessage();
      }
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public Builder setPrice(com.google.type.Money value) {
      if (priceBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        price_ = value;
        onChanged();
      } else {
        priceBuilder_.setMessage(value);
      }

      return this;
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public Builder setPrice(
        com.google.type.Money.Builder builderForValue) {
      if (priceBuilder_ == null) {
        price_ = builderForValue.build();
        onChanged();
      } else {
        priceBuilder_.setMessage(builderForValue.build());
      }

      return this;
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public Builder mergePrice(com.google.type.Money value) {
      if (priceBuilder_ == null) {
        if (price_ != null) {
          price_ =
            com.google.type.Money.newBuilder(price_).mergeFrom(value).buildPartial();
        } else {
          price_ = value;
        }
        onChanged();
      } else {
        priceBuilder_.mergeFrom(value);
      }

      return this;
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public Builder clearPrice() {
      if (priceBuilder_ == null) {
        price_ = null;
        onChanged();
      } else {
        price_ = null;
        priceBuilder_ = null;
      }

      return this;
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public com.google.type.Money.Builder getPriceBuilder() {
      
      onChanged();
      return getPriceFieldBuilder().getBuilder();
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    public com.google.type.MoneyOrBuilder getPriceOrBuilder() {
      if (priceBuilder_ != null) {
        return priceBuilder_.getMessageOrBuilder();
      } else {
        return price_ == null ?
            com.google.type.Money.getDefaultInstance() : price_;
      }
    }
    /**
     * <code>.google.type.Money price = 4;</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.google.type.Money, com.google.type.Money.Builder, com.google.type.MoneyOrBuilder> 
        getPriceFieldBuilder() {
      if (priceBuilder_ == null) {
        priceBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.google.type.Money, com.google.type.Money.Builder, com.google.type.MoneyOrBuilder>(
                getPrice(),
                getParentForChildren(),
                isClean());
        price_ = null;
      }
      return priceBuilder_;
    }

    private boolean available_ ;
    /**
     * <code>bool available = 5;</code>
     * @return The available.
     */
    public boolean getAvailable() {
      return available_;
    }
    /**
     * <code>bool available = 5;</code>
     * @param value The available to set.
     * @return This builder for chaining.
     */
    public Builder setAvailable(boolean value) {
      
      available_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>bool available = 5;</code>
     * @return This builder for chaining.
     */
    public Builder clearAvailable() {
      
      available_ = false;
      onChanged();
      return this;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:pt.tecnico.supplier.grpc.Product)
  }

  // @@protoc_insertion_point(class_scope:pt.tecnico.supplier.grpc.Product)
  private static final pt.tecnico.supplier.grpc.Product DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new pt.tecnico.supplier.grpc.Product();
  }

  public static pt.tecnico.supplier.grpc.Product getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<Product>
      PARSER = new com.google.protobuf.AbstractParser<Product>() {
    @java.lang.Override
    public Product parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new Product(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<Product> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<Product> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public pt.tecnico.supplier.grpc.Product getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

