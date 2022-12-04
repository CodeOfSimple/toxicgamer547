package com.zane.smapiinstaller.utils;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.hash.Hashing;
import com.google.common.io.ByteStreams;
import com.google.common.io.CharStreams;
import com.google.common.io.Files;
import com.hjq.language.MultiLanguages;

import org.apache.commons.io.input.BOMInputStream;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.Predicate;

/**
 * 文件工具类
 *
 * @author Zane
 */
public class FileUtils extends org.zeroturnaround.zip.commons.FileUtils {
    /**
     * 读取文本文件
     *
     * @param file 文件
     * @return 文本
     */
    public static String getFileText(File file) {
        try {
            InputStream inputStream = new BOMInputStream(new FileInputStream(file));
            try (InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
                return CharStreams.toString(reader);
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * 读取本地资源或Asset资源
     *
     * @param context  context
     * @param filename 文件名
     * @return 输入流
     * @throws IOException 异常
     */
    public static InputStream getLocalAsset(Context context, String filename) throws IOException {
        File file = new File(context.getFilesDir(), filename);
        if (file.exists()) {
            return new BOMInputStream(new FileInputStream(file));
        }
        return context.getAssets().open(filename);
    }

    /**
     * 尝试获取本地化后的资源文件
     *
     * @param context  context
     * @param filename 文件名
     * @return 输入流
     * @throws IOException 异常
     */
    public static InputStream getLocaledLocalAsset(Context context, String filename) throws IOException {
        try {
            String language = MultiLanguages.getAppLanguage().getLanguage();
            String localedFilename = filename + '.' + language;
            File file = new File(context.getFilesDir(), localedFilename);
            if (file.exists()) {
                return new BOMInputStream(new FileInputStream(file));
            }
            return context.getAssets().open(localedFilename);
        } catch (IOException e) {
            Log.d("LOCALE", "No lo