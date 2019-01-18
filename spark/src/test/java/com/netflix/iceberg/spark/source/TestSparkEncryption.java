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

import com.google.common.collect.ImmutableList;
import com.netflix.iceberg.FileScanTask;
import com.netflix.iceberg.Schema;
import com.netflix.iceberg.Table;
import com.netflix.iceberg.TableProperties;
import com.netflix.iceberg.hadoop.HadoopKeyManager;
import com.netflix.iceberg.hadoop.HadoopTables;
import com.netflix.iceberg.io.CloseableIterable;
import com.netflix.iceberg.spark.SparkSchemaUtil;
import com.netflix.iceberg.types.Types;
import org.apache.hadoop.conf.Configuration;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SaveMode;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.catalyst.expressions.GenericRow;

public class TestSparkEncryption {

  private static final Schema SCHEMA = new Schema(
      ImmutableList.of(
          Types.NestedField.required(8905, "id", Types.IntegerType.get()),
          Types.NestedField.required(8906, "cost", Types.DoubleType.get()),
          Types.NestedField.required(8907, "comments", Types.StringType.get())));

  private static SparkSession spark = null;

  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  @BeforeClass
  public static void startSpark() {
    spark = SparkSession.builder().master("local[2]").getOrCreate();
  }

  @AfterClass
  public static void stopSpark() {
    SparkSession spark = TestSparkEncryption.spark;
    TestSparkEncryption.spark = null;
    spark.stop();
  }

  @Test
  public void testEncryptedWriteAndRead() throws IOException, NoSuchAlgorithmException {
    File tableDir = temp.newFolder("encryption-test-table");
    Dataset<Row> testDataset = spark.createDataFrame(
        ImmutableList.of(
            new GenericRow(new Object[] { 0, 26.75, "N/A"}),
            new GenericRow(new Object[] { 1, 10.80, "For office supplies" }),
            new GenericRow(new Object[] { 2, 30.80, "Refundable" })),
        SparkSchemaUtil.convert(SCHEMA));
    KeyPair keyEncryptionPair = KeyPairGenerator.getInstance(
        HadoopKeyManager.KEY_ENCRYPTION_DEFAULT_ALGORITHM)
        .generateKeyPair();
    Configuration conf = new Configuration();
    String privateKeyEncoded = Base64.getEncoder().encodeToString(
        keyEncryptionPair.getPrivate().getEncoded());
    String publicKeyEncoded = Base64.getEncoder().encodeToString(
        keyEncryptionPair.getPublic().getEncoded());
    conf.set(HadoopKeyManager.PRIVATE_KEY_CONF, privateKeyEncoded);
    conf.set(HadoopKeyManager.PUBLIC_KEY_CONF, publicKeyEncoded);
    Table table = new HadoopTables(conf).create(SCHEMA, tableDir.getAbsolutePath());
    table.updateProperties()
        .set(TableProperties.WRITE_NEW_DATA_ENCRYPTED, "true")
        .set("iceberg.hadoop." + HadoopKeyManager.PRIVATE_KEY_CONF, privateKeyEncoded)
        .set("iceberg.hadoop." + HadoopKeyManager.PUBLIC_KEY_CONF, publicKeyEncoded)
        .commit();
    testDataset.write()
        .mode(SaveMode.Append)
        .option("path", tableDir.getAbsolutePath())
        .option("iceberg.write.format", "parquet")
        .format("iceberg")
        .save(tableDir.getAbsolutePath());
    table.refresh();
    try (CloseableIterable<FileScanTask> files = table.newScan().planFiles()) {
      files.forEach(fileScanTask -> {
        Assert.assertNotNull(
            String.format(
                "Encryption metadata should have been set up for every file. Missed for file with" +
                    " path %s.",
            fileScanTask.file().path()),
            fileScanTask.file().encryption());
      });
    }

    Dataset<Row> testDatasetAsWritten = spark.read()
        .option("path", tableDir.getAbsolutePath())
        .option("iceberg.write.format", "parquet")
        .format("iceberg")
        .load();
    Assert.assertEquals(
        "Dataset contents did not match.",
        testDataset.collectAsList(),
        testDatasetAsWritten.collectAsList());
  }


}
