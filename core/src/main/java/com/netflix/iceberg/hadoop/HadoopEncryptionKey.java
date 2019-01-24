package com.netflix.iceberg.hadoop;

import com.palantir.crypto2.keys.KeyMaterial;

class HadoopEncryptionKey {
  private final KeyMaterial key;
  private final String cipherAlgorithm;

  HadoopEncryptionKey(String cipherAlgorithm, KeyMaterial key) {
    this.cipherAlgorithm = cipherAlgorithm;
    this.key = key;
  }

  KeyMaterial key() {
    return key;
  }

  String cipherAlgorithm() {
    return cipherAlgorithm;
  }
}
