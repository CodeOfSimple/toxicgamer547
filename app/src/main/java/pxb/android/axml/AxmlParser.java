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
    // private Object attrValue[];

    private int attributeCount;

    private IntBuffer attrs;

    private int classAttribute;
    private int fileSize = -1;
    private int idAttribute;
    private ByteBuffer in;
    private int lineNumber;
    private int nameIdx;
    private int nsIdx;

    private int prefixIdx;

    private int[] resourceIds;

    private String[] strings;

    private int styleAttribute;

    private int textIdx;

    public AxmlParser(byte[] data) {
        this(ByteBuffer.wrap(data));
    }

    public AxmlParser(ByteBuffer in) {
        super();
        this.in = in.order(ByteOrder.LITTLE_ENDIAN);
    }

    public int getAttrCount() {
        return attributeCount;
    }

    public int getAttributeCount() {
        return attributeCount;
    }

    public String getAttrName(int i) {
        int idx = attrs.get(i * 5 + 1);
        return strings[idx];

    }

    public String getAttrNs(int i) {
        int idx = attrs.get(i * 5 + 0);
        return idx >= 0 ? strings[idx] : null;
    }

    String getAttrRawString(int i) {
        int idx = attrs.get(i * 5 + 2);
        if (idx >= 0) {
            return strings[idx];
        }
        return null;
    }

    public int getAttrResId(int i) {
        if (resourceIds != null) {
            int idx = attrs.get(i * 5 + 1);
            if (idx >= 0 && idx < resourceIds.length) {
                return resourceIds[idx];
            }
        }
        return -1;
    }

    public int getAttrType(int i) {
        return attrs.get(i * 5 + 3) >> 24;
    }

    public Object getAttrValue(int i) {
        int v = attrs.get(i * 5 + 4);

        if (i == idAttribute) {
            return ValueWrapper.wrapId(v, getAttrRawString(i));
        } else if (i == styleAttribute) {
            return ValueWrapper.wrapStyle(v, getAttrRawString(i));
        } else i