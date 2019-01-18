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

package com.netflix.iceberg.spark.source;

import com.google.common.collect.Maps;
import com.netflix.iceberg.BaseTable;
import com.netflix.iceberg.encryption.EncryptionBuilders;
import com.netflix.iceberg.encryption.EncryptionKeyMetadata;
import com.netflix.iceberg.encryption.KeyManager;
import com.netflix.iceberg.encryption.PhysicalEncryptionKey;
import com.netflix.iceberg.io.FileIO;
import com.netflix.iceberg.Files;
import com.netflix.iceberg.PartitionSpec;
import com.netflix.iceberg.Schema;
import com.netflix.iceberg.Snapshot;
import com.netflix.iceberg.TableMetadata;
import com.netflix.iceberg.TableOperations;
import com.netflix.iceberg.exceptions.AlreadyExistsException;
import com.netflix.iceberg.exceptions.CommitFailedException;
import com.netflix.iceberg.exceptions.RuntimeIOException;
import com.netflix.iceberg.io.InputFile;
import com.netflix.iceberg.io.OutputFile;
import com.netflix.iceberg.util.ByteBuffers;
import com.palantir.crypto2.cipher.AesCtrCipher;
import com.palantir.crypto2.cipher.SeekableCipherFactory;
import com.palantir.crypto2.keys.KeyMaterial;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

// TODO: Use the copy of this from core.
class TestTables {
  private TestTables() {
  }

  static TestTable create(File temp, String name, Schema schema, PartitionSpec spec) {
    TestTableOperations ops = new TestTableOperations(name);
    if (ops.current() != null) {
      throw new AlreadyExistsException("Table %s already exists at location: %s", name, temp);
    }
    ops.commit(null, TableMetadata.newTableMetadata(ops, schema, spec, temp.toString()));
    return new TestTable(ops, name);
  }

  static TestTable load(String name) {
    TestTableOperations ops = new TestTableOperations(name);
    if (ops.current() == null) {
      return null;
    }
    return new TestTable(ops, name);
  }

  static boolean drop(String name) {
    synchronized (METADATA) {
      return METADATA.remove(name) != null;
    }
  }

  static class TestTable extends BaseTable {
    private final TestTableOperations ops;

    private TestTable(TestTableOperations ops, String name) {
      super(ops, name);
      this.ops = ops;
    }

    @Override
    public TestTableOperations operations() {
      return ops;
    }
  }

  private static final Map<String, TableMetadata> METADATA = Maps.newHashMap();

  static void clearTables() {
    synchronized (METADATA) {
      METADATA.clear();
    }
  }

  static TableMetadata readMetadata(String tableName) {
    synchronized (METADATA) {
      return METADATA.get(tableName);
    }
  }

  static void replaceMetadata(String tableName, TableMetadata metadata) {
    synchronized (METADATA) {
      METADATA.put(tableName, metadata);
    }
  }

  static class TestTableOperations implements TableOperations {

    private final String tableName;
    private TableMetadata current = null;
    private long lastSnapshotId = 0;
    private int failCommits = 0;

    TestTableOperations(String tableName) {
      this.tableName = tableName;
      refresh();
      if (current != null) {
        for (Snapshot snap : current.snapshots()) {
          this.lastSnapshotId = Math.max(lastSnapshotId, snap.snapshotId());
        }
      } else {
        this.lastSnapshotId = 0;
      }
    }

    void failCommits(int numFailures) {
      this.failCommits = numFailures;
    }

    @Override
    public TableMetadata current() {
      return current;
    }

    @Override
    public TableMetadata refresh() {
      synchronized (METADATA) {
        this.current = METADATA.get(tableName);
      }
      return current;
    }

    @Override
    public void commit(TableMetadata base, TableMetadata metadata) {
      if (base != current) {
        throw new CommitFailedException("Cannot commit changes based on stale metadata");
      }
      synchronized (METADATA) {
        refresh();
        if (base == current) {
          if (failCommits > 0) {
            this.failCommits -= 1;
            throw new CommitFailedException("Injected failure");
          }
          METADATA.put(tableName, metadata);
          this.current = metadata;
        } else {
          throw new CommitFailedException(
              "Commit failed: table was updated at %d", base.lastUpdatedMillis());
        }
      }
    }

    @Override
    public FileIO io() {
      return new LocalFileIO();
    }

    @Override
    public KeyManager keys() {
      return new LocalKeyManager();
    }

    @Override
    public String metadataFileLocation(String fileName) {
      return new File(new File(current.location(), "metadata"), fileName).getAbsolutePath();
    }

    @Override
    public long newSnapshotId() {
      long nextSnapshotId = lastSnapshotId + 1;
      this.lastSnapshotId = nextSnapshotId;
      return nextSnapshotId;
    }
  }
  
  static class LocalFileIO implements FileIO {

    @Override
    public InputFile newInputFile(String path) {
      return Files.localInput(path);
    }

    @Override
    public OutputFile newOutputFile(String path) {
      return Files.localOutput(new File(path));
    }

    @Override
    public void deleteFile(String path) {
      if (!new File(path).delete()) {
        throw new RuntimeIOException("Failed to delete file: " + path);
      }
    }
  }

  static class LocalKeyManager implements KeyManager {

    @Override
    public PhysicalEncryptionKey getEncryptionKey(EncryptionKeyMetadata encryptionMetadata) {
      String keyMetadataPath = new String(
          ByteBuffers.toByteArray(encryptionMetadata.keyMetadata()), StandardCharsets.UTF_8);
      String keyFile = String.format("%s.key", keyMetadataPath);
      byte[] secretKeyBytes;
      byte[] iv;
      try (FileInputStream keyStream = new FileInputStream(keyFile);
           InputStreamReader keyStreamReader = new InputStreamReader(keyStream, StandardCharsets.UTF_8);
           BufferedReader keyReader = new BufferedReader(keyStreamReader)) {
        secretKeyBytes = Base64.getDecoder().decode(keyReader.readLine());
        iv = Base64.getDecoder().decode(keyReader.readLine());
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
      return EncryptionBuilders.physicalEncryptionKeyBuilder()
          .keyMetadata(encryptionMetadata)
          .secretKeyBytes(secretKeyBytes)
          .iv(iv)
          .build();
    }

    @Override
    public PhysicalEncryptionKey createAndStoreEncryptionKey(String path) {
      KeyMaterial newKey = SeekableCipherFactory.generateKeyMaterial(
          AesCtrCipher.ALGORITHM);
      EncryptionKeyMetadata keyMetadata = EncryptionBuilders.encryptionKeyMetadataBuilder()
          .keyMetadata(path.getBytes(StandardCharsets.UTF_8))
          .keyAlgorithm(newKey.getSecretKey().getAlgorithm())
          .cipherAlgorithm(AesCtrCipher.ALGORITHM)
          .build();

      String keyFile = String.format("%s.key", path);
      try (FileOutputStream keyStream = new FileOutputStream(new File(keyFile));
           OutputStreamWriter keyStreamWriter =
               new OutputStreamWriter(keyStream, StandardCharsets.UTF_8);
           BufferedWriter keyWriter = new BufferedWriter(keyStreamWriter)) {
        keyWriter.write(
            Base64.getEncoder().encodeToString(newKey.getSecretKey().getEncoded()));
        keyWriter.newLine();
        keyWriter.write(Base64.getEncoder().encodeToString(newKey.getIv()));
      } catch (IOException e) {
        throw new RuntimeIOException(e);
      }
      return EncryptionBuilders.physicalEncryptionKeyBuilder()
          .keyMetadata(keyMetadata)
          .secretKeyBytes(newKey.getSecretKey().getEncoded())
          .iv(newKey.getIv())
          .build();
    }
  }
}
