/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.apksig.internal.zip;

import com.android.apksig.internal.util.Pair;
import com.android.apksig.util.DataSource;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.CRC32;
import java.util.zip.Deflater;

/**
 * Assorted ZIP format helpers.
 *
 * <p>NOTE: Most helper methods operating on {@code ByteBuffer} instances expect that the byte
 * order of these buffers is little-endian.
 */
public abstract class ZipUtils {
    private ZipUtils() {}

    public static final short COMPRESSION_METHOD_STORED = 0;
    public static final short COMPRESSION_METHOD_DEFLATED = 8;

    public static final short GP_FLAG_DATA_DESCRIPTOR_USED = 0x08;
    public static final short GP_FLAG_EFS = 0x0800;

    private static final int ZIP_EOCD_REC_MIN_SIZE = 22;
    private static final int ZIP_EOCD_REC_SIG = 0x0