package com.apkbuilder.app;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.content.FileProvider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends AppCompatActivity {

    private static final int REQUEST_PICK_JAVA = 1001;
    private static final int REQUEST_PICK_MANIFEST = 1002;
    private static final int REQUEST_PERMISSIONS = 1003;

    private EditText etPackageName, etAppName;
    private TextView tvLog, tvJavaStatus, tvManifestStatus, tvStatusBadge;
    private Button btnBuild, btnLoadJava, btnLoadManifest;
    private ProgressBar progressBar;
    private ScrollView scrollLog;

    private File javaFile = null;
    private File manifestFile = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        etPackageName = findViewById(R.id.et_package_name);
        etAppName = findViewById(R.id.et_app_name);
        tvLog = findViewById(R.id.tv_log);
        tvJavaStatus = findViewById(R.id.tv_java_status);
        tvManifestStatus = findViewById(R.id.tv_manifest_status);
        tvStatusBadge = findViewById(R.id.tv_status_badge);
        btnBuild = findViewById(R.id.btn_build);
        btnLoadJava = findViewById(R.id.btn_load_java);
        btnLoadManifest = findViewById(R.id.btn_load_manifest);
        progressBar = findViewById(R.id.progress_bar);
        scrollLog = findViewById(R.id.scroll_log);

        btnLoadJava.setOnClickListener(v -> pickFile(REQUEST_PICK_JAVA));
        btnLoadManifest.setOnClickListener(v -> pickFile(REQUEST_PICK_MANIFEST));
        btnBuild.setOnClickListener(v -> startBuild());

        checkPermissions();
    }

    private void checkPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivity(intent);
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                        new String[]{
                                Manifest.permission.READ_EXTERNAL_STORAGE,
                                Manifest.permission.WRITE_EXTERNAL_STORAGE
                        }, REQUEST_PERMISSIONS);
            }
        }
    }

    private void pickFile(int requestCode) {
        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("*/*");
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        startActivityForResult(Intent.createChooser(intent, "Select File"), requestCode);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null) return;

        Uri uri = data.getData();
        if (uri == null) return;

        try {
            File destDir = new File(getFilesDir(), "input");
            destDir.mkdirs();

            if (requestCode == REQUEST_PICK_JAVA) {
                javaFile = new File(destDir, "MainActivity.java");
                copyUriToFile(uri, javaFile);
                tvJavaStatus.setText("✓ " + getFileName(uri));
                tvJavaStatus.setTextColor(0xFF3FB950);
                appendLog("Loaded Java file: " + getFileName(uri));
            } else if (requestCode == REQUEST_PICK_MANIFEST) {
                manifestFile = new File(destDir, "AndroidManifest.xml");
                copyUriToFile(uri, manifestFile);
                tvManifestStatus.setText("✓ " + getFileName(uri));
                tvManifestStatus.setTextColor(0xFF3FB950);
                appendLog("Loaded Manifest: " + getFileName(uri));
            }
        } catch (IOException e) {
            appendLog("ERROR loading file: " + e.getMessage());
        }
    }

    private void startBuild() {
        String packageName = etPackageName.getText().toString().trim();
        String appName = etAppName.getText().toString().trim();

        if (packageName.isEmpty() || appName.isEmpty()) {
            Toast.makeText(this, "Fill in package name and app name", Toast.LENGTH_SHORT).show();
            return;
        }

        if (javaFile == null || !javaFile.exists()) {
            Toast.makeText(this, "Please load a .java file first", Toast.LENGTH_SHORT).show();
            return;
        }

        new BuildTask().execute(packageName, appName);
    }

    private class BuildTask extends AsyncTask<String, Object, File> {

        @Override
        protected void onPreExecute() {
            btnBuild.setEnabled(false);
            btnBuild.setText("Building...");
            progressBar.setVisibility(View.VISIBLE);
            progressBar.setProgress(0);
            tvStatusBadge.setText("BUILDING");
            tvStatusBadge.setTextColor(0xFFF0883E);
            clearLog();
            appendLog("=== APK Build Started ===\n");
        }

        @Override
        protected File doInBackground(String... params) {
            String packageName = params[0];
            String appName = params[1];

            try {
                ApkCompiler compiler = new ApkCompiler(
                        MainActivity.this,
                        packageName,
                        appName,
                        javaFile,
                        manifestFile,
                        (progress, message) -> publishProgress(progress, message)
                );
                return compiler.build();
            } catch (Exception e) {
                publishProgress(-1, "BUILD FAILED: " + e.getMessage());
                return null;
            }
        }

        @Override
        protected void onProgressUpdate(Object... values) {
            int progress = (int) values[0];
            String message = (String) values[1];
            appendLog(message);
            if (progress >= 0) {
                progressBar.setProgress(progress);
            }
        }

        @Override
        protected void onPostExecute(File apkFile) {
            btnBuild.setEnabled(true);
            btnBuild.setText("⚡ BUILD APK");

            if (apkFile != null && apkFile.exists()) {
                progressBar.setProgress(100);
                tvStatusBadge.setText("SUCCESS");
                tvStatusBadge.setTextColor(0xFF3FB950);
                appendLog("\n=== BUILD SUCCESSFUL ===");
                appendLog("APK saved to: " + apkFile.getAbsolutePath());
                appendLog("\nTap INSTALL to install the app.");

                // Change button to install
                btnBuild.setText("📦 INSTALL APK");
                btnBuild.setEnabled(true);
                btnBuild.setOnClickListener(v -> installApk(apkFile));
            } else {
                tvStatusBadge.setText("FAILED");
                tvStatusBadge.setTextColor(0xFFF85149);
                appendLog("\n=== BUILD FAILED ===");
                appendLog("Check log above for errors.");
                progressBar.setVisibility(View.GONE);
                btnBuild.setOnClickListener(v -> startBuild());
            }
        }
    }

    private void installApk(File apkFile) {
        Uri apkUri = FileProvider.getUriForFile(this,
                getPackageName() + ".provider", apkFile);

        Intent intent = new Intent(Intent.ACTION_VIEW);
        intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
        intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
        startActivity(intent);
    }

    private void appendLog(String message) {
        runOnUiThread(() -> {
            tvLog.append(message + "\n");
            scrollLog.post(() -> scrollLog.fullScroll(View.FOCUS_DOWN));
        });
    }

    private void clearLog() {
        runOnUiThread(() -> tvLog.setText(""));
    }

    private void copyUriToFile(Uri uri, File dest) throws IOException {
        try (InputStream in = getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[4096];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
        }
    }

    private String getFileName(Uri uri) {
        String path = uri.getPath();
        if (path == null) return "file";
        return path.substring(path.lastIndexOf('/') + 1);
    }
}
