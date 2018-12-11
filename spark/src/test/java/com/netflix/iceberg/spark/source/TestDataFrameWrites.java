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

import com.google.common.collect.Lists;
import com.netflix.iceberg.Files;
import com.netflix.iceberg.PartitionSpec;
import com.netflix.iceberg.Schema;
import com.netflix.iceberg.Table;
import com.netflix.iceberg.TableProperties;
import com.netflix.iceberg.avro.Avro;
import com.netflix.iceberg.avro.AvroIterable;
import com.netflix.iceberg.hadoop.HadoopTables;
import com.netflix.iceberg.io.FileAppender;
import com.netflix.iceberg.spark.data.AvroDataTest;
import com.netflix.iceberg.spark.data.RandomData;
import com.netflix.iceberg.spark.data.SparkAvroReader;
import com.netflix.iceberg.types.Types;
import org.apache.avro.generic.GenericData.Record;
import org.apache.hadoop.conf.Configuration;
import org.apache.spark.api.java.JavaRDD;
import org.apache.spark.api.java.JavaSparkContext;
import org.apache.spark.sql.DataFrameWriter;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;
import org.apache.spark.sql.catalyst.InternalRow;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.List;

import static com.netflix.iceberg.spark.SparkSchemaUtil.convert;
import static com.netflix.iceberg.spark.data.TestHelpers.assertEqualsSafe;
import static com.netflix.iceberg.spark.data.TestHelpers.assertEqualsUnsafe;

@RunWith(Parameterized.class)
public class TestDataFrameWrites extends AvroDataTest {
  private static final Configuration CONF = new Configuration();
  private static final Schema BASIC_SCHEMA = new Schema(
      Types.NestedField.required(0, "id", Types.LongType.get()),
      Types.NestedField.optional(1, "data", Types.ListType.ofOptional(2, Types.StringType.get())));

  private String format = null;

  @Parameterized.Parameters
  public static Object[][] parameters() {
    return new Object[][] {
        new Object[] { "parquet" },
        new Object[] { "avro" }
    };
  }

  public TestDataFrameWrites(String format) {
    this.format = format;
  }

  private static SparkSession spark = null;
  private static JavaSparkContext sc = null;

  @BeforeClass
  public static void startSpark() {
    TestDataFrameWrites.spark = SparkSession.builder().master("local[2]").getOrCreate();
    TestDataFrameWrites.sc = new JavaSparkContext(spark.sparkContext());
  }

  @AfterClass
  public static void stopSpark() {
    SparkSession spark = TestDataFrameWrites.spark;
    TestDataFrameWrites.spark = null;
    TestDataFrameWrites.sc = null;
    spark.stop();
  }

  @Override
  protected void writeAndValidate(Schema schema) throws IOException {
    writeAndValidateWithLocations(schema, false, false);
  }

  @Test
  public void testWrite_overridingDataLocation_tablePropertyOnly() throws IOException {
    writeAndValidateWithLocations(BASIC_SCHEMA, true, false);
  }

  @Test
  public void testWrite_overridingDataLocation_sourceOptionOnly() throws IOException {
    writeAndValidateWithLocations(BASIC_SCHEMA, false, true);
  }

  @Test
  public void testWrite_overridingDataLocation_sourceOptionTakesPrecedence() throws IOException {
    writeAndValidateWithLocations(BASIC_SCHEMA, true, true);
  }

  private void writeAndValidateWithLocations(
      Schema schema,
      boolean setTablePropertyDataLocation,
      boolean setWriterOptionDataLocation) throws IOException {
    File parent = temp.newFolder("parquet");
    File location = new File(parent, "test");
    Assert.assertTrue("Mkdir should succeed", location.mkdirs());

    File tablePropertyDataLocation = new File(parent, "test-table-property-data-dir");
    Assert.assertTrue("Mkdir should succeed", tablePropertyDataLocation.mkdirs());
    File writerPropertyDataLocation = new File(parent, "test-source-option-data-dir");
    Assert.assertTrue("Mkdir should succeed", writerPropertyDataLocation.mkdirs());

    HadoopTables tables = new HadoopTables(CONF);
    Table table = tables.create(schema, PartitionSpec.unpartitioned(), location.toString());
    Schema tableSchema = table.schema(); // use the table schema because ids are reassigned

    table.updateProperties().set(TableProperties.DEFAULT_FILE_FORMAT, format).commit();
    if (setTablePropertyDataLocation) {
      table.updateProperties().set(
          TableProperties.WRITE_NEW_DATA_LOCATION, tablePropertyDataLocation.getAbsolutePath()).commit();
    }

    List<Record> expected = RandomData.generateList(tableSchema, 100, 0L);
    Dataset<Row> df = createDataset(expected, tableSchema);
    DataFrameWriter<?> writer = df.write().format("iceberg").mode("append");
    if (setWriterOptionDataLocation) {
      writer = writer.option(TableProperties.WRITE_NEW_DATA_LOCATION, writerPropertyDataLocation.getAbsolutePath());
    }

    writer.save(location.toString());

    table.refresh();

    Dataset<Row> result = spark.read()
        .format("iceberg")
        .load(location.toString());

    List<Row> actual = result.collectAsList();

    Assert.assertEquals("Result size should match expected", expected.size(), actual.size());
    for (int i = 0; i < expected.size(); i += 1) {
      assertEqualsSafe(tableSchema.asStruct(), expected.get(i), actual.get(i));
    }

    File expectedDataDir;
    if (setWriterOptionDataLocation) {
      expectedDataDir = writerPropertyDataLocation;
    } else if (setTablePropertyDataLocation) {
      expectedDataDir = tablePropertyDataLocation;
    } else {
      expectedDataDir = new File(location, "data");
    }
    table.currentSnapshot().addedFiles().forEach(dataFile ->
        Assert.assertTrue(
            String.format(
                "File should have the parent directory %s, but has: %s.",
                expectedDataDir.getAbsolutePath(),
                dataFile.path()),
            URI.create(dataFile.path().toString()).getPath().startsWith(expectedDataDir.getAbsolutePath())));
  }

  private Dataset<Row> createDataset(List<Record> records, Schema schema) throws IOException {
    // this uses the SparkAvroReader to create a DataFrame from the list of records
    // it assumes that SparkAvroReader is correct
    File testFile = temp.newFile();
    Assert.assertTrue("Delete should succeed", testFile.delete());

    try (FileAppender<Record> writer = Avro.write(Files.localOutput(testFile))
        .schema(schema)
        .named("test")
        .build()) {
      for (Record rec : records) {
        writer.add(rec);
      }
    }

    List<InternalRow> rows;
    try (AvroIterable<InternalRow> reader = Avro.read(Files.localInput(testFile))
        .createReaderFunc(SparkAvroReader::new)
        .project(schema)
        .build()) {
      rows = Lists.newArrayList(reader);
    }

    // make sure the dataframe matches the records before moving on
    for (int i = 0; i < records.size(); i += 1) {
      assertEqualsUnsafe(schema.asStruct(), records.get(i), rows.get(i));
    }

    JavaRDD<InternalRow> rdd = sc.parallelize(rows);
    return spark.internalCreateDataFrame(JavaRDD.toRDD(rdd), convert(schema), false);
  }
}
