/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.netflix.iceberg.hadoop;

import com.google.common.base.Preconditions;
import com.google.common.collect.Maps;
import com.netflix.iceberg.TableProperties;
import com.netflix.iceberg.encryption.EncryptedInputFile;
import com.netflix.iceberg.encryption.EncryptedOutputFile;
import com.netflix.iceberg.encryption.EncryptedOutputFiles;
import com.netflix.iceberg.encryption.EncryptionKeyMetadata;
import com.netflix.iceberg.encryption.EncryptionKeyMetadatas;
import com.netflix.iceberg.encryption.EncryptionManager;
import com.netflix.iceberg.exceptions.RuntimeIOException;
import com.netflix.iceberg.io.InputFile;
import com.netflix.iceberg.io.OutputFile;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.FileKeyStorageStrategy;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyPairs;
import com.palantir.crypto2.keys.KeyStorageStrategy;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Map;

/**
 * Default key manager implementation for {@link HadoopTableOperations}
 * and {@link com.netflix.iceberg.BaseMetastoreTableOperations}.
 * <p>
 * This implementation is meant to be a very basic implementation of key management,
 * without any assumptions about having an external key storage solution. However, in
 * practice this solution would likely be insecure for most production scenarios. This is
 * particularly because this implementation requires the master key pair for decrypting keys
 * to be stored in the Hadoop configuration, which is impractical for any truly secure
 * environment. In short then this implementation serves as a sort-of filler and ought to be
 * replaced by more secure means like KMS. This implementation also assumes that each file
 * will have exactly one key.
 *
 * TODO(#81) Provide a KMS-backed key manager out of the box as well.
 */
public class HadoopEncryptionManager implements EncryptionManager {

  public static final String KEY_ENCRYPTION_ALGORITHM_CONF =
      "iceberg.fs.encrypt.key.encryptKeyAlgorithm";
  public static final String KEY_ENCRYPTION_DEFAULT_ALGORITHM = "RSA";
  public static final String PUBLIC_KEY_CONF = "iceberg.fs.encrypt.key.public";
  public static final String PRIVATE_KEY_CONF = "iceberg.fs.encrypt.key.private";

  private final SerializableConfiguration conf;
  private final String cipherAlgorithm;
  private transient Map<URI, KeyStorageStrategy> fsUrisToKeyStores;

  public static HadoopEncryptionManager fromTableProperties(
      Configuration conf, Map<String, String> tableProperties) {
    String cipherAlgorithm = tableProperties.getOrDefault(
        TableProperties.CIPHER_ALGORITHM,
        TableProperties.DEFAULT_CIPHER_ALGORITHM);
    return new HadoopEncryptionManager(conf, cipherAlgorithm);
  }

  public HadoopEncryptionManager(Configuration conf, String cipherAlgorithm) {
    this.conf = new SerializableConfiguration(conf);
    this.cipherAlgorithm = cipherAlgorithm;
    this.fsUrisToKeyStores = Maps.newConcurrentMap();
  }

  @Override
  public InputFile decrypt(EncryptedInputFile encrypted) {
    return HadoopCryptoStreamReader.decrypt(
        encrypted.encryptedInputFile(),
        getKey(encrypted.keyMetadata()));
  }

  @Override
  public EncryptedOutputFile encrypt(OutputFile rawOutput) {
    KeyMaterial newKey = SeekableCipherFactory.generateKeyMaterial(cipherAlgorithm);
    HadoopEncryptionKey asIcebergEncryptionKey = new HadoopEncryptionKey(
        cipherAlgorithm, newKey);
    String location = rawOutput.location();
    EncryptionKeyMetadata keyMetadata = encodeKeyMetadata(
        asIcebergEncryptionKey, location);
    KeyStorageStrategy keyStore = getKeyStore(location);
    keyStore.put(location, newKey);
    OutputFile encryptingOutput = HadoopCryptoStreamWriter.encrypt(rawOutput, asIcebergEncryptionKey);
    return EncryptedOutputFiles.of(encryptingOutput, keyMetadata);
  }

  private HadoopEncryptionKey getKey(EncryptionKeyMetadata keyMetadata) {
    ByteBuffer metadataBuffer = keyMetadata.keyMetadata().asReadOnlyBuffer();
    int ivSize = metadataBuffer.getInt();
    byte[] iv = new byte[ivSize];
    metadataBuffer.get(iv, 0, ivSize);
    String cipherAlgorithm = readUtf8AndAdvanceBufferPosition(metadataBuffer);
    String filePath = readUtf8AndAdvanceBufferPosition(metadataBuffer);
    KeyStorageStrategy keyStore = getKeyStore(filePath);
    KeyMaterial key = keyStore.get(filePath);
    return new HadoopEncryptionKey(cipherAlgorithm, key);
  }

  private EncryptionKeyMetadata encodeKeyMetadata(HadoopEncryptionKey key, String path) {
    byte[] cipherAlgorithmUtf8Bytes = key.cipherAlgorithm().getBytes(StandardCharsets.UTF_8);
    byte[] pathBytes = path.getBytes(StandardCharsets.UTF_8);
    ByteBuffer keyMetadataBuffer = ByteBuffer.allocate(
        cipherAlgorithmUtf8Bytes.length
        + pathBytes.length
        + key.key().getIv().length
        + 12);
    ByteBuffer keyMetadataBufferResult = keyMetadataBuffer.asReadOnlyBuffer();
    writeBytes(key.key().getIv(), keyMetadataBuffer);
    writeBytes(cipherAlgorithmUtf8Bytes, keyMetadataBuffer);
    writeBytes(pathBytes, keyMetadataBuffer);
    return EncryptionKeyMetadatas.of(keyMetadataBufferResult);
  }

  private void writeBytes(byte[] bytes, ByteBuffer encodingBuffer) {
    encodingBuffer.putInt(bytes.length);
    encodingBuffer.put(bytes);
  }

  private KeyStorageStrategy getKeyStore(String fileUri) {
    Path keyMetadataAsPath = new Path(fileUri);
    KeyStorageStrategy keyStore;
    try {
      keyStore = fsUrisToKeyStores.computeIfAbsent(
          keyMetadataAsPath.getFileSystem(conf.get()).getUri(),
          scheme -> initializeKeyStore(conf.get(), keyMetadataAsPath));
    } catch (IOException e) {
      throw new RuntimeIOException(e);
    }
    return keyStore;
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    fsUrisToKeyStores = Maps.newConcurrentMap();
  }

  private static KeyStorageStrategy initializeKeyStore(Configuration conf, Path path) {
    // Check lazily because we won't invoke the key manager unless we're told to encrypt something
    // at the table level.
    String encryptKeyAlgorithm = conf.get(
        KEY_ENCRYPTION_ALGORITHM_CONF, KEY_ENCRYPTION_DEFAULT_ALGORITHM);
    String encodedPublicKey = conf.get(PUBLIC_KEY_CONF);
    Preconditions.checkNotNull(
        encodedPublicKey,
        "Public key must be provided via %s in the Hadoop configuration.",
        PUBLIC_KEY_CONF);
    // Private key can be null if only encrypting and writing.
    String encodedPrivateKey = conf.get(PRIVATE_KEY_CONF);
    KeyPair keyPair = KeyPairs.fromStrings(encodedPrivateKey, encodedPublicKey, encryptKeyAlgorithm);
    FileSystem fs = Util.getFS(path, conf);
    return new FileKeyStorageStrategy(fs, keyPair);
  }

  private static String readUtf8AndAdvanceBufferPosition(ByteBuffer buf) {
    int stringSize = buf.getInt();
    ByteBuffer stringBuffer = buf.slice();
    stringBuffer.limit(stringSize);
    String result = StandardCharsets.UTF_8.decode(stringBuffer).toString();
    buf.position(buf.position() + stringSize);
    return result;
  }

}
