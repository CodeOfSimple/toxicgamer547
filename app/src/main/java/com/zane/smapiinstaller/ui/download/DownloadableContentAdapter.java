package com.zane.smapiinstaller.ui.download;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import com.lmntrx.android.library.livin.missme.ProgressDialog;
import com.lzy.okgo.OkGo;
import com.lzy.okgo.callback.FileCallback;
import com.lzy.okgo.model.Progress;
import com.lzy.okgo.model.Response;
import com.microsoft.appcenter.crashes.Crashes;
import com.zane.smapiinstaller.R;
import com.zane.smapiinstaller.constant.DialogAction;
import com.zane.smapiinstaller.constant.DownloadableContentTypeConstants;
import com.zane.smapiinstaller.databinding.DownloadContentItemBinding;
import com.zane.smapiinstaller.entity.DownloadableContent;
import com.zane.smapiinstaller.entity.ModManifestEntry;
import com.zane.smapiinstaller.logic.ModAssetsManager;
import com.zane.smapiinstaller.utils.DialogUtils;
import com.zane.smapiinstaller.utils.FileUtils;

import org.apache.commons.lang3.StringUtils;
import org.zeroturnaround.zip.ZipUtil;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

/**
 * {@link RecyclerView.Adapter} that can display a {@link DownloadableContent}
 *
 * @author Zane
 */
public class DownloadableContentAdapter extends RecyclerView.Adapter<DownloadableContentAdapter.ViewHolder> {

    private List<DownloadableContent> downloadableContentList;

    public void setDownloadableContentList(List<DownloadableContent> downloadableContentList) {
        this.downloadableContentList = downloadableContentList;
        notifyDataSetChanged();
    }

    public DownloadableContentAdapter(List<DownloadableContent> items) {
        downloadableContentList = items;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.download_content_item, parent, false);
        return new ViewHolder(view);
    }

    @Override
    public void onBindViewHolder(final ViewHolder holder, int position) {
        holder.setDownloadableContent(downloadableContentList.get(position));
    }

    @Override
    public int getItemCount() {
        return downloadableContentList.size();
    }

    static class ViewHolder extends RecyclerView.ViewHolder {
        private final DownloadContentItemBinding binding;

        private final AtomicBoolean downloading = new AtomicBoolean(false);

        public DownloadableContent downloadableContent;

        public void setDownloadableContent(DownloadableContent downloadableContent) {
            this.downloadableContent = downloadableContent;
            binding.textItemType.setText(downloadableContent.getType());
            binding.textItemName.setText(downloadableContent.getName());
            binding.textItemDescription.setText(downloadableContent.getDescription());
            if (StringUtils.isNoneBlank(downloadableContent.getAssetPath())) {
                File contentFile = new File(itemView.getContext().getFilesDir(), downloadableContent.getAssetPath());
                if (contentFile.exists()) {
                    Context context = itemView.getContext();
                    File file = new File(context.getCacheDir(), downloadableContent.getName() + ".zip");
                    if (!file.exists() || !StringUtils.equalsIgnoreCase(FileUtils.getFileHash(file), downloadableContent.getHash())) {
                        binding.buttonRemoveContent.setVisibility(View.VISIBLE);
                        binding.buttonDownloadContent.setVisibility(View.VISIBLE);
                        return;
                    }
                    binding.buttonRemoveContent.setVisibility(View.VISIBLE);
                    binding.buttonDownloadContent.setVisibility(View.INVISIBLE);
                    return;
                }
            }
            binding.buttonRemoveContent.setVisibility(View.INVISIBLE);
            binding.buttonDownloadContent.setVisibility(View.VISIBLE);
        }

        public ViewHolder(View view) {
            super(view);
            binding = DownloadContentItemBinding.bind(view);
            binding.buttonRemoveContent.setOnClickListener(v -> removeContent());
            binding.buttonDownloadContent.setOnClickListener(v -> downloadContent());
        }

        void removeContent() {
            if (StringUtils.isNoneBlank(downloadableContent.getAssetPath())) {
                File contentFile = new File(itemView.getContext().getFilesDir(), downloadableContent.ge