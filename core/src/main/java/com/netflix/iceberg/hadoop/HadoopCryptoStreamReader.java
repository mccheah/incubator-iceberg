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

import com.netflix.iceberg.io.InputFile;
import com.netflix.iceberg.io.SeekableInputStream;
import com.palantir.crypto2.io.CryptoStreamFactory;
import com.palantir.crypto2.io.DefaultSeekableInputStream;
import com.palantir.seekio.SeekableInput;

import java.io.IOException;

class HadoopCryptoStreamReader {

  static SeekableInputStream decrypt(
      SeekableInputStream original, HadoopEncryptionKey key) {
    return SeekableInputCompat.of(
        CryptoStreamFactory.decrypt(
            SeekableInputCompat.of(original),
            key.key(),
            key.cipherAlgorithm()));
  }

  static InputFile decrypt(InputFile original, HadoopEncryptionKey key) {
    if (original instanceof HadoopInputFile) {
      // To keep this as an instance of HadoopInputFile, as logic specific to this InputFile
      // type is present throughout the project.
      return ((HadoopInputFile) original).decrypt(key);
    } else {
      return new DecryptingInputFile(original, key);
    }
  }

  private static abstract class SeekableInputCompat
      extends SeekableInputStream implements SeekableInput {

    static SeekableInput of(SeekableInputStream delegate) {
      return new SeekableInputStreamAdapter(delegate);
    }

    static SeekableInputStream of(SeekableInput delegate) {
      return new SeekableInputAdapter(delegate);
    }
  }

  private static final class SeekableInputStreamAdapter extends SeekableInputCompat {
    private final SeekableInputStream delegate;

    private SeekableInputStreamAdapter(SeekableInputStream delegate) {
      this.delegate = delegate;
    }

    @Override
    public long getPos() throws IOException {
      return delegate.getPos();
    }

    @Override
    public void seek(long newPos) throws IOException {
      delegate.seek(newPos);
    }

    @Override
    public int read() throws IOException {
      return delegate.read();
    }
  }

  private static final class SeekableInputAdapter extends SeekableInputCompat {
    private final DefaultSeekableInputStream delegate;

    private SeekableInputAdapter(SeekableInput delegate) {
      this.delegate = new DefaultSeekableInputStream(delegate);
    }

    @Override
    public long getPos() throws IOException {
      return delegate.getPos();
    }

    @Override
    public void seek(long newPos) throws IOException {
      delegate.seek(newPos);
    }

    @Override
    public int read() throws IOException {
      return delegate.read();
    }
  }

  private static final class DecryptingInputFile implements InputFile {

    private final InputFile delegate;
    private final HadoopEncryptionKey key;

    DecryptingInputFile(
        InputFile delegate, HadoopEncryptionKey key) {
      this.delegate = delegate;
      this.key = key;
    }

    @Override
    public long getLength() {
      // Note that this isn't entirely accurate - the length of the decrypted bytes will be
      // adjusted due to the padding that is inherent to encryption. But throughout the
      // project the slightly inaccurate length doesn't seem to impact correctness. It would
      // be more ideal to try to calculate this length more accurately in the future.
      return delegate.getLength();
    }

    @Override
    public SeekableInputStream newStream() {
      return decrypt(delegate.newStream(), key);
    }

    @Override
    public String location() {
      return delegate.location();
    }
  }

  private HadoopCryptoStreamReader() {}
}
