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
                dialog.setMessage(activity.getString(message));
            }
        });
    }

    /**
     * 显示警告对话框
     *
     * @param view    context容器
     * @param title   标题
     * @param message 消息
     */
    public static void showAlertDialog(View view, int title, String message) {
        CommonLogic.runOnUiThread(CommonLogic.getActivityFromView(view), (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR()).title(title, null).message(null, message, null).positiveButton(R.string.ok, null, null);
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }
    public static void showAlertDialog(Activity context, int title, String message) {
        CommonLogic.runOnUiThread(context, (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR()).title(title, null).message(null, message, null).positiveButton(R.string.ok, null, null);
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }

    /**
     * 显示警告对话框
     *
     * @param view    context容器
     * @param title   标题
     * @param message 消息
     */
    public static void showAlertDialog(View view, int title, int message) {
        CommonLogic.runOnUiThread(CommonLogic.getActivityFromView(view), (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR()).title(title, null).message(message, null, null).positiveButton(R.string.ok, null, null);
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }

    public static void showAlertDialog(Activity context, int title, int message) {
        CommonLogic.runOnUiThread(context, (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR()).title(title, null).message(message, null, null).positiveButton(R.string.ok, null, null);
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }

    /**
     * 显示确认对话框
     *
     * @param view     context容器
     * @param title    标题
     * @param message  消息
     * @param callback 回调
     */
    public static void showConfirmDialog(View view, int title, int message, BiConsumer<MaterialDialog, DialogAction> callback) {
        showConfirmDialog(CommonLogic.getActivityFromView(view), title, message, callback);
    }
    public static void showConfirmDialog(Activity context, int title, int message, BiConsumer<MaterialDialog, DialogAction> callback) {
        CommonLogic.runOnUiThread(context, (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR()).title(title, null).message(message, null, null).positiveButton(R.string.confirm, null, dialog -> {
                callback.accept(dialog, DialogAction.POSITIVE);
                return null;
            }).negativeButton(R.string.cancel, null, dialog -> {
                callback.accept(dialog, DialogAction.NEGATIVE);
                return null;
            });
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }

    /**
     * 显示确认对话框
     *
     * @param view     context容器
     * @param title    标题
     * @param message  消息
     * @param callback 回调
     */
    public static void showConfirmDialog(View view, int title, String message, BiConsumer<MaterialDialog, DialogAction> callback) {
        showConfirmDialog(view, title, message, R.string.confirm, R.string.cancel, callback);
    }

    /**
     * 显示确认对话框
     *
     * @param view         context容器
     * @param title        标题
     * @param message      消息
     * @param positiveText 确认文本
     * @param negativeText 取消文本
     * @param callback     回调
     */
    public static void showConfirmDialog(View view, int title, String message, int positiveText, int negativeText, BiConsumer<MaterialDialog, DialogAction> callback) {
        showConfirmDialog(view, title, message, positiveText, negativeText, false, callback);
    }

    public static void showConfirmDialog(View view, int title, String message, int positiveText, int negativeText, boolean isHtml, BiConsumer<MaterialDialog, DialogAction> callback) {
        CommonLogic.runOnUiThread(CommonLogic.getActivityFromView(view), (activity) -> {
            MaterialDialog materialDialog = new MaterialDialog(activity, MaterialDialog.getDEFAULT_BEHAVIOR())
                    .title(title, null)
                    .positiveButton(positiveText, null, dialog -> {
                        callback.accept(dialog, DialogAction.POSITIVE);
                        return null;
                    }).negativeButton(negativeText, null, dialog -> {
                        callback.accept(dialog, DialogAction.NEGATIVE);
                        return null;
                    });
            if(isHtml){
                materialDialog.message(null, message, (dialogMessageSettings) -> {
                    dialogMessageSettings.html(null);
                    return null;
                });
            }
            else {
                materialDialog.message(null, message, null);
            }
            DialogUtils.setCurrentDialog(materialDialog);
            materialDialog.show();
        });
    }

    /**
     * 显示进度条
     *
     * @param view    context容器
     * @param title   标题
     * @param message 消息
     * @return 对话框引用
     */
    public static AtomicReference<ProgressDialog> showProgressDialog(View view, int title, String message) {
        AtomicReference<ProgressDialog> reference = new AtomicReference<>();
        CommonLogic.runOnUiThread(CommonLogic.getActivityFromView(view), (activity) -> {
            ProgressDialog dialog = new ProgressDialog(activity);
            DialogUtils.setCurrentDialog(dialog);
      