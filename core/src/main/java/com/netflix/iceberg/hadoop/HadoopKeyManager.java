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
import com.netflix.iceberg.encryption.EncryptionBuilders;
import com.netflix.iceberg.encryption.EncryptionKeyMetadata;
import com.netflix.iceberg.encryption.KeyManager;
import com.netflix.iceberg.encryption.PhysicalEncryptionKey;
import com.palantir.crypto2.cipher.SeekableCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.hadoop.FileKeyStorageStrategy;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.KeyPairs;
import com.palantir.crypto2.keys.KeyStorageStrategy;
import com.palantir.crypto2.keys.serialization.KeyMaterials;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;

import java.io.IOException;
import java.io.ObjectInputStream;
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
class HadoopKeyManager implements KeyManager {

  public static final String KEY_ENCRYPTION_ALGORITHM_CONF =
      "iceberg.fs.encrypt.key.encryptKeyAlgorithm";
  public static final String KEY_ENCRYPTION_DEFAULT_ALGORITHM = "RSA";
  public static final String PUBLIC_KEY_CONF = "iceberg.fs.encrypt.key.public";
  public static final String PRIVATE_KEY_CONF = "iceberg.fs.encrypt.key.private";

  private final SerializableConfiguration conf;
  private final String cipherAlgorithm;
  private transient Map<String, KeyStorageStrategy> fsSchemesToKeyStores;

  public static HadoopKeyManager fromTableProperties(
      Configuration conf, Map<String, String> tableProperties) {
    String cipherAlgorithm = tableProperties.getOrDefault(
        TableProperties.CIPHER_ALGORITHM,
        TableProperties.DEFAULT_CIPHER_ALGORITHM);
    Preconditions.checkNotNull(
        conf.get(PUBLIC_KEY_CONF),
        "Public key must be provided via %s in the Hadoop configuration.",
        PUBLIC_KEY_CONF);
    return new HadoopKeyManager(conf, cipherAlgorithm);
  }

  public HadoopKeyManager(Configuration conf, String cipherAlgorithm) {
    this.conf = new SerializableConfiguration(conf);
    this.cipherAlgorithm = cipherAlgorithm;
    this.fsSchemesToKeyStores = Maps.newConcurrentMap();
  }

  @Override
  public PhysicalEncryptionKey getEncryptionKey(EncryptionKeyMetadata keyMetadata) {
    String keyMetadataAsString = StandardCharsets
        .UTF_8
        .decode(keyMetadata.keyMetadata()).toString();
    Path keyMetadataAsPath = new Path(keyMetadataAsString);
    KeyStorageStrategy keyStore = fsSchemesToKeyStores.computeIfAbsent(
        keyMetadataAsPath.toUri().getScheme(),
        scheme -> initializeKeyStore(conf.get(), keyMetadataAsPath));
    KeyMaterial storeKey = keyStore.get(keyMetadataAsString);
    return toIcebergPhysicalKey(keyMetadata, storeKey);
  }

  private PhysicalEncryptionKey toIcebergPhysicalKey(
      EncryptionKeyMetadata encryptionMetadata, KeyMaterial storeKey) {
    return EncryptionBuilders.physicalEncryptionKeyBuilder()
        .keyMetadata(encryptionMetadata)
        .secretKeyBytes(storeKey.getSecretKey().getEncoded())
        .iv(storeKey.getIv())
        .build();
  }

  @Override
  public PhysicalEncryptionKey createAndStoreEncryptionKey(String path) {
    KeyMaterial newKey = SeekableCipherFactory.generateKeyMaterial(cipherAlgorithm);
    EncryptionKeyMetadata keyMetadata = EncryptionBuilders.encryptionKeyMetadataBuilder()
        .keyMetadata(path.getBytes(StandardCharsets.UTF_8))
        .keyAlgorithm(newKey.getSecretKey().getAlgorithm())
        .cipherAlgorithm(cipherAlgorithm)
        .build();
    Path hadoopPath = new Path(path);
    KeyStorageStrategy keyStore = fsSchemesToKeyStores.computeIfAbsent(
        hadoopPath.toUri().getScheme(),
        scheme -> initializeKeyStore(conf.get(), hadoopPath));
    keyStore.put(path, newKey);
    return toIcebergPhysicalKey(keyMetadata, newKey);
  }

  private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
    input.defaultReadObject();
    fsSchemesToKeyStores = Maps.newConcurrentMap();
  }

  private static KeyStorageStrategy initializeKeyStore(Configuration conf, Path path) {
    String encryptKeyAlgorithm = conf.get(
        KEY_ENCRYPTION_ALGORITHM_CONF, KEY_ENCRYPTION_DEFAULT_ALGORITHM);
    String encodedPublicKey = conf.get(PUBLIC_KEY_CONF);
    // Private key can be null if only encrypting and writing.
    String encodedPrivateKey = conf.get(PRIVATE_KEY_CONF);
    KeyPair keyPair = KeyPairs.fromStrings(encodedPrivateKey, encodedPublicKey, encryptKeyAlgorithm);
    FileSystem fs = Util.getFS(path, conf);
    return new FileKeyStorageStrategy(fs, keyPair);
  }
}
