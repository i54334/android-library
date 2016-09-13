package com.github.axet.androidlibrary.services;

import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ProviderInfo;
import android.content.pm.ResolveInfo;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.CancellationSignal;
import android.provider.OpenableColumns;
import android.support.annotation.Nullable;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FileProvider extends android.support.v4.content.FileProvider {
    static final String[] COLUMNS = {OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE};

    static Map<Uri, String> types = new HashMap<>();
    static Map<Uri, String> names = new HashMap<>();
    static Map<Uri, File> files = new HashMap<>();
    static ProviderInfo info;

    @Override
    public void attachInfo(Context context, ProviderInfo info) {
        super.attachInfo(context, info);
        FileProvider.info = info;
    }

    @Nullable
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder, CancellationSignal cancellationSignal) {
        if (projection == null) {
            projection = COLUMNS;
        }

        String[] cols = new String[projection.length];
        Object[] values = new Object[projection.length];
        int i = 0;
        for (String col : projection) {
            if (OpenableColumns.DISPLAY_NAME.equals(col)) {
                cols[i] = OpenableColumns.DISPLAY_NAME;
                values[i++] = names.get(uri);
            } else if (OpenableColumns.SIZE.equals(col)) {
                cols[i] = OpenableColumns.SIZE;
                values[i++] = files.get(uri).length();
            }
        }

        cols = copyOf(cols, i);
        values = copyOf(values, i);

        final MatrixCursor cursor = new MatrixCursor(cols, 1);
        cursor.addRow(values);
        return cursor;
    }

    @Override
    public String getType(Uri uri) {
        return types.get(uri);
    }

    public static Uri getUriForFile(Context context, String type, String name, File file) {
        Uri u = android.support.v4.content.FileProvider.getUriForFile(context, info.authority, file);
        types.put(u, type);
        names.put(u, name);
        files.put(u, file);
        return u;
    }

    public static void grantPermissions(Context context, Intent intent) {
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        Object uri = intent.getExtras().get(Intent.EXTRA_STREAM);

        if (uri instanceof Uri) {
            grantPermissions(context, intent, (Uri) uri);
        }
        if (uri instanceof ArrayList) {
            for (Uri u : (ArrayList<Uri>) uri)
                grantPermissions(context, intent, u);
        }
    }


    public static void grantPermissions(Context context, Intent intent, Uri u) {
        List<ResolveInfo> resInfoList = context.getPackageManager().queryIntentActivities(intent, PackageManager.MATCH_DEFAULT_ONLY);
        for (ResolveInfo resolveInfo : resInfoList) {
            String packageName = resolveInfo.activityInfo.packageName;
            context.grantUriPermission(packageName, u, Intent.FLAG_GRANT_READ_URI_PERMISSION);
        }
    }

    private static String[] copyOf(String[] original, int newLength) {
        final String[] result = new String[newLength];
        System.arraycopy(original, 0, result, 0, newLength);
        return result;
    }

    private static Object[] copyOf(Object[] original, int newLength) {
        final Object[] result = new Object[newLength];
        System.arraycopy(original, 0, result, 0, newLength);
        return result;
    }
}
