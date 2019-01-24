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

import com.google.common.io.CountingOutputStream;
import com.netflix.iceberg.hadoop.HadoopOutputFile;
import com.netflix.iceberg.io.InputFile;
import com.netflix.iceberg.io.OutputFile;
import com.netflix.iceberg.io.PositionOutputStream;
import com.netflix.iceberg.util.ByteBuffers;
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.keys.KeyMaterial;
import com.palantir.crypto2.keys.serialization.KeyMaterials;

import java.io.IOException;
import java.io.OutputStream;

public class CryptoStreamWriter {

  public static PositionOutputStream encrypt(
      PositionOutputStream delegate, HadoopEncryptionKey key) {
    OutputStream encryptedOutputStream = CryptoStreamFactory.encrypt(
        delegate,
        key.key(),
        key.cipherAlgorithm());
    return new CountingPositionOutputStream(encryptedOutputStream);
  }

  public static OutputFile encrypt(OutputFile delegate, HadoopEncryptionKey key) {
    if (delegate instanceof HadoopOutputFile) {
      return ((HadoopOutputFile) delegate).encrypt(key);
    } else {
      return new EncryptedOutputFile(delegate, key);
    }
  }

  private static final class EncryptedOutputFile implements OutputFile {
    private final OutputFile delegate;
    private final HadoopEncryptionKey key;

    private EncryptedOutputFile(OutputFile delegate, HadoopEncryptionKey key) {
      this.delegate = delegate;
      this.key = key;
    }

    @Override
    public PositionOutputStream create() {
      return encrypt(delegate.create(), key);
    }

    @Override
    public PositionOutputStream createOrOverwrite() {
      return encrypt(delegate.createOrOverwrite(), key);
    }

    @Override
    public String location() {
      return delegate.location();
    }

    @Override
    public InputFile toInputFile() {
      return HadoopCryptoStreamReader.decrypt(delegate.toInputFile(), key);
    }
  }

  private static final class CountingPositionOutputStream extends PositionOutputStream {
    private final CountingOutputStream delegateCounting;

    public CountingPositionOutputStream(OutputStream delegate) {
      this.delegateCounting = new CountingOutputStream(delegate);
    }

    @Override
    public long getPos() {
      return delegateCounting.getCount();
    }

    @Override
    public void write(int b) throws IOException {
      delegateCounting.write(b);
    }
  }

}
