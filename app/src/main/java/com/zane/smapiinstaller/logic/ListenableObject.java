package com.zane.smapiinstaller.logic;

import java.util.List;

import java.util.function.Predicate;

/**
 * @author Zane
 */
public interface ListenableObject<T> {
    /**
     * 返回一个当前已注册的监听器列表
     * @return 监听器列表
     */
    List<Predicate<T>> getOnChangedListenerL