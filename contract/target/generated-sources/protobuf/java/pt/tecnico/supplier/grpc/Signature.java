// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: supplier.proto

package pt.tecnico.supplier.grpc;

/**
 * Protobuf type {@code pt.tecnico.supplier.grpc.Signature}
 */
public  final class Signature extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:pt.tecnico.supplier.grpc.Signature)
    SignatureOrBuilder {
private static final long serialVersionUID = 0L;
  // Use Signature.newBuilder() to construct.
  private Signature(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private Signature() {
    signerId_ = "";
    value_ = com.google.protobuf.ByteString.EMPTY;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new Signature();
  }

  @java.lang.Override
  public final com.google.protobuf.UnknownFieldSet
  getUnknownFields() {
    return this.unknownFields;
  }
  private Signature(
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

            signerId_ = s;
            break;
          }
          case 18: {

            value_ = input.readBytes();
            break;
          }
          case 24: {

            nonce_ = input.readInt64();
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
    return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Signature_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Signature_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            pt.tecnico.supplier.grpc.Signature.class, pt.tecnico.supplier.grpc.Signature.Builder.class);
  }

  public static final int SIGNERID_FIELD_NUMBER = 1;
  private volatile java.lang.Object signerId_;
  /**
   * <code>string signerId = 1;</code>
   * @return The signerId.
   */
  public java.lang.String getSignerId() {
    java.lang.Object ref = signerId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      signerId_ = s;
      return s;
    }
  }
  /**
   * <code>string signerId = 1;</code>
   * @return The bytes for signerId.
   */
  public com.google.protobuf.ByteString
      getSignerIdBytes() {
    java.lang.Object ref = signerId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      signerId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int VALUE_FIELD_NUMBER = 2;
  private com.google.protobuf.ByteString value_;
  /**
   * <code>bytes value = 2;</code>
   * @return The value.
   */
  public com.google.protobuf.ByteString getValue() {
    return value_;
  }

  public static final int NONCE_FIELD_NUMBER = 3;
  private long nonce_;
  /**
   * <code>int64 nonce = 3;</code>
   * @return The nonce.
   */
  public long getNonce() {
    return nonce_;
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
    if (!getSignerIdBytes().isEmpty()) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, signerId_);
    }
    if (!value_.isEmpty()) {
      output.writeBytes(2, value_);
    }
    if (nonce_ != 0L) {
      output.writeInt64(3, nonce_);
    }
    unknownFields.writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!getSignerIdBytes().isEmpty()) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, signerId_);
    }
    if (!value_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(2, value_);
    }
    if (nonce_ != 0L) {
      size += com.google.protobuf.CodedOutputStream
        .computeInt64Size(3, nonce_);
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
    if (!(obj instanceof pt.tecnico.supplier.grpc.Signature)) {
      return super.equals(obj);
    }
    pt.tecnico.supplier.grpc.Signature other = (pt.tecnico.supplier.grpc.Signature) obj;

    if (!getSignerId()
        .equals(other.getSignerId())) return false;
    if (!getValue()
        .equals(other.getValue())) return false;
    if (getNonce()
        != other.getNonce()) return false;
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
    hash = (37 * hash) + SIGNERID_FIELD_NUMBER;
    hash = (53 * hash) + getSignerId().hashCode();
    hash = (37 * hash) + VALUE_FIELD_NUMBER;
    hash = (53 * hash) + getValue().hashCode();
    hash = (37 * hash) + NONCE_FIELD_NUMBER;
    hash = (53 * hash) + com.google.protobuf.Internal.hashLong(
        getNonce());
    hash = (29 * hash) + unknownFields.hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Signature parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Signature parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static pt.tecnico.supplier.grpc.Signature parseFrom(
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
  public static Builder newBuilder(pt.tecnico.supplier.grpc.Signature prototype) {
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
   * Protobuf type {@code pt.tecnico.supplier.grpc.Signature}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:pt.tecnico.supplier.grpc.Signature)
      pt.tecnico.supplier.grpc.SignatureOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Signature_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Signature_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              pt.tecnico.supplier.grpc.Signature.class, pt.tecnico.supplier.grpc.Signature.Builder.class);
    }

    // Construct using pt.tecnico.supplier.grpc.Signature.newBuilder()
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
      signerId_ = "";

      value_ = com.google.protobuf.ByteString.EMPTY;

      nonce_ = 0L;

      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return pt.tecnico.supplier.grpc.SupplierProtobuf.internal_static_pt_tecnico_supplier_grpc_Signature_descriptor;
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Signature getDefaultInstanceForType() {
      return pt.tecnico.supplier.grpc.Signature.getDefaultInstance();
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Signature build() {
      pt.tecnico.supplier.grpc.Signature result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public pt.tecnico.supplier.grpc.Signature buildPartial() {
      pt.tecnico.supplier.grpc.Signature result = new pt.tecnico.supplier.grpc.Signature(this);
      result.signerId_ = signerId_;
      result.value_ = value_;
      result.nonce_ = nonce_;
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
      if (other instanceof pt.tecnico.supplier.grpc.Signature) {
        return mergeFrom((pt.tecnico.supplier.grpc.Signature)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(pt.tecnico.supplier.grpc.Signature other) {
      if (other == pt.tecnico.supplier.grpc.Signature.getDefaultInstance()) return this;
      if (!other.getSignerId().isEmpty()) {
        signerId_ = other.signerId_;
        onChanged();
      }
      if (other.getValue() != com.google.protobuf.ByteString.EMPTY) {
        setValue(other.getValue());
      }
      if (other.getNonce() != 0L) {
        setNonce(other.getNonce());
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
      pt.tecnico.supplier.grpc.Signature parsedMessage = null;
      try {
        parsedMessage = PARSER.parsePartialFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        parsedMessage = (pt.tecnico.supplier.grpc.Signature) e.getUnfinishedMessage();
        throw e.unwrapIOException();
      } finally {
        if (parsedMessage != null) {
          mergeFrom(parsedMessage);
        }
      }
      return this;
    }

    private java.lang.Object signerId_ = "";
    /**
     * <code>string signerId = 1;</code>
     * @return The signerId.
     */
    public java.lang.String getSignerId() {
      java.lang.Object ref = signerId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        signerId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string signerId = 1;</code>
     * @return The bytes for signerId.
     */
    public com.google.protobuf.ByteString
        getSignerIdBytes() {
      java.lang.Object ref = signerId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        signerId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string signerId = 1;</code>
     * @param value The signerId to set.
     * @return This builder for chaining.
     */
    public Builder setSignerId(
        java.lang.String value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      signerId_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>string signerId = 1;</code>
     * @return This builder for chaining.
     */
    public Builder clearSignerId() {
      
      signerId_ = getDefaultInstance().getSignerId();
      onChanged();
      return this;
    }
    /**
     * <code>string signerId = 1;</code>
     * @param value The bytes for signerId to set.
     * @return This builder for chaining.
     */
    public Builder setSignerIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  checkByteStringIsUtf8(value);
      
      signerId_ = value;
      onChanged();
      return this;
    }

    private com.google.protobuf.ByteString value_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>bytes value = 2;</code>
     * @return The value.
     */
    public com.google.protobuf.ByteString getValue() {
      return value_;
    }
    /**
     * <code>bytes value = 2;</code>
     * @param value The value to set.
     * @return This builder for chaining.
     */
    public Builder setValue(com.google.protobuf.ByteString value) {
      if (value == null) {
    throw new NullPointerException();
  }
  
      value_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>bytes value = 2;</code>
     * @return This builder for chaining.
     */
    public Builder clearValue() {
      
      value_ = getDefaultInstance().getValue();
      onChanged();
      return this;
    }

    private long nonce_ ;
    /**
     * <code>int64 nonce = 3;</code>
     * @return The nonce.
     */
    public long getNonce() {
      return nonce_;
    }
    /**
     * <code>int64 nonce = 3;</code>
     * @param value The nonce to set.
     * @return This builder for chaining.
     */
    public Builder setNonce(long value) {
      
      nonce_ = value;
      onChanged();
      return this;
    }
    /**
     * <code>int64 nonce = 3;</code>
     * @return This builder for chaining.
     */
    public Builder clearNonce() {
      
      nonce_ = 0L;
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


    // @@protoc_insertion_point(builder_scope:pt.tecnico.supplier.grpc.Signature)
  }

  // @@protoc_insertion_point(class_scope:pt.tecnico.supplier.grpc.Signature)
  private static final pt.tecnico.supplier.grpc.Signature DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new pt.tecnico.supplier.grpc.Signature();
  }

  public static pt.tecnico.supplier.grpc.Signature getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<Signature>
      PARSER = new com.google.protobuf.AbstractParser<Signature>() {
    @java.lang.Override
    public Signature parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      return new Signature(input, extensionRegistry);
    }
  };

  public static com.google.protobuf.Parser<Signature> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<Signature> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public pt.tecnico.supplier.grpc.Signature getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

