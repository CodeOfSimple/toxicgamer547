package com.zane.smapiinstaller.logic;

import android.view.View;

import com.hjq.language.MultiLanguages;
import com.lzy.okgo.OkGo;
import com.lzy.okgo.callback.StringCallback;
import com.lzy.okgo.model.Response;
import com.zane.smapiinstaller.entity.UpdatableList;
import com.zane.smapiinstaller.utils.FileUtils;
import com.zane.smapiinstaller.utils.JsonUtil;

import org.apache.commons.lang3.StringUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import java.util.function.Predicate;

/**
 * 在线列表更新管理器
 * @author Zane
 * @param <T> 列表类型
 */
public class UpdatableListManager<T extends UpdatableList> implements ListenableObject<T> {
    private static final ConcurrentHashMap<Class<?>, Boolean> updateChecked = new ConcurrentHashMap<>();

    private static UpdatableList updatableList = null;

    private final List<Predicate<T>> onChangedListener = new Array