package com.zane.smapiinstaller.utils;

import android.util.Log;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * JSON工具类
 * @author Zane
 */
public class JsonUtil {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    static {
        // 允许未定义的属性
        MAPPER.con