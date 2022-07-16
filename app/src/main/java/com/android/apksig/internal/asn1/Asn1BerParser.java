
/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.apksig.internal.asn1;

import com.android.apksig.internal.asn1.ber.BerDataValue;
import com.android.apksig.internal.asn1.ber.BerDataValueFormatException;
import com.android.apksig.internal.asn1.ber.BerDataValueReader;
import com.android.apksig.internal.asn1.ber.BerEncoding;
import com.android.apksig.internal.asn1.ber.ByteBufferBerDataValueReader;
import com.android.apksig.internal.util.ByteBufferUtils;
import com.zane.smapiinstaller.utils.MathUtils;
import com.zane.smapiinstaller.utils.ReflectionUtils;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Parser of ASN.1 BER-encoded structures.
 *
 * <p>Structure is described to the parser by providing a class annotated with {@link Asn1Class},
 * containing fields annotated with {@link Asn1Field}.
 */
public final class Asn1BerParser {
    private Asn1BerParser() {}

    /**
     * Returns the ASN.1 structure contained in the BER encoded input.
     *
     * @param encoded encoded input. If the decoding operation succeeds, the position of this buffer
     *        is advanced to the first position following the end of the consumed structure.
     * @param containerClass class describing the structure of the input. The class must meet the
     *        following requirements:
     *        <ul>
     *        <li>The class must be annotated with {@link Asn1Class}.</li>
     *        <li>The class must expose a public no-arg constructor.</li>
     *        <li>Member fields of the class which are populated with parsed input must be
     *            annotated with {@link Asn1Field} and be public and non-final.</li>
     *        </ul>
     *
     * @throws Asn1DecodingException if the input could not be decoded into the specified Java
     *         object
     */
    public static <T> T parse(ByteBuffer encoded, Class<T> containerClass)
            throws Asn1DecodingException {
        BerDataValue containerDataValue;
        try {
            containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
        } catch (BerDataValueFormatException e) {
            throw new Asn1DecodingException("Failed to decode top-level data value", e);
        }
        if (containerDataValue == null) {
            throw new Asn1DecodingException("Empty input");
        }
        return parse(containerDataValue, containerClass);
    }

    /**
     * Returns the implicit {@code SET OF} contained in the provided ASN.1 BER input. Implicit means
     * that this method does not care whether the tag number of this data structure is
     * {@code SET OF} and whether the tag class is {@code UNIVERSAL}.
     *
     * <p>Note: The returned type is {@link List} rather than {@link java.util.Set} because ASN.1
     * SET may contain duplicate elements.
     *
     * @param encoded encoded input. If the decoding operation succeeds, the position of this buffer
     *        is advanced to the first position following the end of the consumed structure.
     * @param elementClass class describing the structure of the values/elements contained in this
     *        container. The class must meet the following requirements:
     *        <ul>
     *        <li>The class must be annotated with {@link Asn1Class}.</li>
     *        <li>The class must expose a public no-arg constructor.</li>
     *        <li>Member fields of the class which are populated with parsed input must be
     *            annotated with {@link Asn1Field} and be public and non-final.</li>
     *        </ul>
     *
     * @throws Asn1DecodingException if the input could not be decoded into the specified Java
     *         object
     */
    public static <T> List<T> parseImplicitSetOf(ByteBuffer encoded, Class<T> elementClass)
            throws Asn1DecodingException {
        BerDataValue containerDataValue;
        try {
            containerDataValue = new ByteBufferBerDataValueReader(encoded).readDataValue();
        } catch (BerDataValueFormatException e) {
            throw new Asn1DecodingException("Failed to decode top-level data value", e);
        }
        if (containerDataValue == null) {
            throw new Asn1DecodingException("Empty input");
        }
        return parseSetOf(containerDataValue, elementClass);
    }

    private static <T> T parse(BerDataValue container, Class<T> containerClass)
            throws Asn1DecodingException {
        if (container == null) {
            throw new NullPointerException("container == null");
        }
        if (containerClass == null) {
            throw new NullPointerException("containerClass == null");
        }

        Asn1Type dataType = getContainerAsn1Type(containerClass);
        switch (dataType) {
            case CHOICE:
                return parseChoice(container, containerClass);

            case SEQUENCE:
            {
                int expectedTagClass = BerEncoding.TAG_CLASS_UNIVERSAL;
                int expectedTagNumber = BerEncoding.getTagNumber(dataType);
                if ((container.getTagClass() != expectedTagClass)
                        || (container.getTagNumber() != expectedTagNumber)) {
                    throw new Asn1UnexpectedTagException(
                            "Unexpected data value read as " + containerClass.getName()
                                    + ". Expected " + BerEncoding.tagClassAndNumberToString(
                                    expectedTagClass, expectedTagNumber)
                                    + ", but read: " + BerEncoding.tagClassAndNumberToString(
                                    container.getTagClass(), container.getTagNumber()));
                }
                return parseSequence(container, containerClass);
            }
            case UNENCODED_CONTAINER:
                return parseSequence(container, containerClass, true);
            default:
                throw new Asn1DecodingException("Parsing container " + dataType + " not supported");
        }
    }

    private static <T> T parseChoice(BerDataValue dataValue, Class<T> containerClass)
            throws Asn1DecodingException {
        List<AnnotatedField> fields = getAnnotatedFields(containerClass);
        if (fields.isEmpty()) {
            throw new Asn1DecodingException(
                    "No fields annotated with " + Asn1Field.class.getName()
                            + " in CHOICE class " + containerClass.getName());
        }

        // Check that class + tagNumber don't clash between the choices
        for (int i = 0; i < fields.size() - 1; i++) {
            AnnotatedField f1 = fields.get(i);
            int tagNumber1 = f1.getBerTagNumber();
            int tagClass1 = f1.getBerTagClass();
            for (int j = i + 1; j < fields.size(); j++) {
                AnnotatedField f2 = fields.get(j);
                int tagNumber2 = f2.getBerTagNumber();
                int tagClass2 = f2.getBerTagClass();
                if ((tagNumber1 == tagNumber2) && (tagClass1 == tagClass2)) {
                    throw new Asn1DecodingException(
                            "CHOICE fields are indistinguishable because they have the same tag"
                                    + " class and number: " + containerClass.getName()
                                    + "." + f1.getField().getName()
                                    + " and ." + f2.getField().getName());
                }
            }
        }

        // Instantiate the container object / result
        T obj;
        try {
            obj = containerClass.getConstructor().newInstance();
        } catch (IllegalArgumentException | ReflectiveOperationException e) {
            throw new Asn1DecodingException("Failed to instantiate " + containerClass.getName(), e);
        }
        // Set the matching field's value from the data value
        for (AnnotatedField field : fields) {
            try {
                field.setValueFrom(dataValue, obj);
                return obj;
            } catch (Asn1UnexpectedTagException expected) {
                // not a match
            }
        }

        throw new Asn1DecodingException(
                "No options of CHOICE " + containerClass.getName() + " matched");
    }

    private static <T> T parseSequence(BerDataValue container, Class<T> containerClass)
            throws Asn1DecodingException {
        return parseSequence(container, containerClass, false);
    }

    private static <T> T parseSequence(BerDataValue container, Class<T> containerClass,
            boolean isUnencodedContainer) throws Asn1DecodingException {
        List<AnnotatedField> fields = getAnnotatedFields(containerClass);
        Collections.sort(
                fields, (f1, f2) -> f1.getAnnotation().index() - f2.getAnnotation().index());
        // Check that there are no fields with the same index
        if (fields.size() > 1) {
            AnnotatedField lastField = null;
            for (AnnotatedField field : fields) {
                if ((lastField != null)
                        && (lastField.getAnnotation().index() == field.getAnnotation().index())) {