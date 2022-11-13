package com.zane.smapiinstaller.utils;

import android.app.Activity;
import android.text.InputType;
import android.view.View;

import com.afollestad.materialdialogs.MaterialDialog;
import com.afollestad.materialdialogs.input.DialogInputExtKt;
import com.afollestad.materialdialogs.list.DialogListExtKt;
import com.afollestad.materialdialogs.list.DialogSingleChoiceExtKt;
import com.lmntrx.android.library.livin.missme.ProgressDialog;
import com.microsoft.appcenter.crashes.Crashes;
import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.constant.DialogAction;
import com.zane.smapiinstaller.logic.CommonLogic;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import java.util.function.BiConsumer;

/**
 * 对话框相关工具类
 *
 * @author Zane
 */
public class DialogUtils {
    private static Object currentDialog = null;

    public static Object getCurrentDialog() {
        return currentDialog;
    }

    public static void setCurrentDialog(Object currentDialog) {
        DialogUtils.currentDialog = currentDialog;
    }

    /**
     * 设置进度条状态
     *
     * @param view     context容器
     * @param dialog   对话框
     * @param message  消息
     * @param progress 进度
     */
    public static void setProgressDialogState(View view, ProgressDialog dialog, Integer message, Integer progress) {
        CommonLogic.runOnUiThread(CommonLogic.getActivityFromView(view), (activity) -> {
            if (progress != null) {
                dialog.setProgress(progress);
            }
            if (message != null) {
                dialog.setMessage(ac