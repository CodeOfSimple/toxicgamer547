/*
 * Copyright (c) 2009-2013 Panxiaobo
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
package pxb.android.axml;

import static pxb.android.axml.NodeVisitor.TYPE_INT_BOOLEAN;
import static pxb.android.axml.NodeVisitor.TYPE_STRING;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;

import pxb.android.ResConst;
import pxb.android.StringItems;

/**
 * a class to read android axml
 * 
 * @author <a href="mailto:pxb1988@gmail.com">Panxiaobo</a>
 */
public class AxmlParser implements ResConst {

    public static final int END_FILE = 7;
    public static final int END_NS = 5;
    public static final int END_TAG = 3;
    public static final int START_FILE = 1;
    public static final int START_NS = 4;
    public static final int START_TAG = 2;
    public static final int TEXT = 6;
    // private int attrName[];
    // private int attrNs[];
    // private int attrResId[];
    // private int attrType[];
  