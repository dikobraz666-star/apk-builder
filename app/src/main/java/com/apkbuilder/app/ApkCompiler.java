package com.apkbuilder.app;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.math.BigInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ApkCompiler {

    public interface BuildCallback {
        void onProgress(int percent, String message);
    }

    private final Context context;
    private final String packageName;
    private final String appName;
    private final File javaFile;
    private final File manifestFile;
    private final BuildCallback callback;

    private File buildDir;
    private File classesDir;
    private File outputDir;

    public ApkCompiler(Context context, String packageName, String appName,
                       File javaFile, File manifestFile, BuildCallback callback) {
        this.context = context;
        this.packageName = packageName;
        this.appName = appName;
        this.javaFile = javaFile;
        this.manifestFile = manifestFile;
        this.callback = callback;
    }

    public File build() throws Exception {
        setupDirs();

        log(5, "Step 1/5: Preparing build environment...");
        prepareEnvironment();

        log(20, "Step 2/5: Compiling Java source...");
        compileJava();

        log(45, "Step 3/5: Converting to DEX bytecode...");
        convertToDex();

        log(65, "Step 4/5: Packaging APK...");
        File unsignedApk = packageApk();

        log(85, "Step 5/5: Signing APK...");
        File signedApk = signApk(unsignedApk);

        log(100, "Done! APK size: " + (signedApk.length() / 1024) + " KB");
        return signedApk;
    }

    private void setupDirs() throws IOException {
        buildDir = new File(context.getCacheDir(), "build_" + System.currentTimeMillis());
        classesDir = new File(buildDir, "classes");
        outputDir = new File(context.getFilesDir(), "output");

        buildDir.mkdirs();
        classesDir.mkdirs();
        outputDir.mkdirs();
    }

    private void prepareEnvironment() throws Exception {
        File androidJar = new File(buildDir, "android.jar");
        if (!androidJar.exists()) {
            log(8, "Extracting android.jar...");
            extractAsset("android.jar", androidJar);
        }

        File dxJar = new File(buildDir, "dx.jar");
        if (!dxJar.exists()) {
            log(12, "Extracting dx.jar...");
            extractAsset("dx.jar", dxJar);
        }

        File ecjJar = new File(buildDir, "ecj.jar");
        if (!ecjJar.exists()) {
            log(14, "Extracting ecj.jar...");
            extractAsset("ecj.jar", ecjJar);
        }

        log(15, "Environment ready.");
    }

    private void compileJava() throws Exception {
        File androidJar = new File(buildDir, "android.jar");
        File ecjJar = new File(buildDir, "ecj.jar");

        File srcDir = new File(buildDir, "src");
        String[] packageParts = packageName.split("\\.");
        File packageDir = srcDir;
        for (String part : packageParts) {
            packageDir = new File(packageDir, part);
        }
        packageDir.mkdirs();

        String javaContent = readFile(javaFile);

        if (!javaContent.startsWith("package " + packageName)) {
            javaContent = "package " + packageName + ";\n\n" +
                    javaContent.replaceFirst("^package [^;]+;\n?", "");
        }

        File srcFile = new File(packageDir, getMainClassName(javaContent) + ".java");
        writeFile(srcFile, javaContent);

        log(25, "Compiling: " + srcFile.getName());

        // Use ECJ via reflection (loaded from extracted ecj.jar)
        java.net.URLClassLoader ecjLoader = new java.net.URLClassLoader(
                new java.net.URL[]{ecjJar.toURI().toURL()},
                ClassLoader.getSystemClassLoader()
        );

        try {
            Class<?> mainClass = ecjLoader.loadClass("org.eclipse.jdt.internal.compiler.batch.Main");
            StringWriter outWriter = new StringWriter();
            StringWriter errWriter = new StringWriter();

            Object ecjMain = mainClass.getConstructor(
                    PrintWriter.class, PrintWriter.class, boolean.class
            ).newInstance(
                    new PrintWriter(outWriter),
                    new PrintWriter(errWriter),
                    false
            );

            String[] args = {
                    "-source", "1.8",
                    "-target", "1.8",
                    "-classpath", androidJar.getAbsolutePath(),
                    "-d", classesDir.getAbsolutePath(),
                    "-encoding", "UTF-8",
                    srcFile.getAbsolutePath()
            };

            boolean success = (boolean) mainClass.getMethod("compile", String[].class)
                    .invoke(ecjMain, (Object) args);

            if (!success) {
                String errors = errWriter.toString();
                if (errors.isEmpty()) errors = outWriter.toString();
                throw new Exception("Compilation failed:\n" + errors);
            }
        } finally {
            ecjLoader.close();
        }

        log(40, "Compilation successful!");

        List<File> classes = listFiles(classesDir, ".class");
        log(42, "Compiled " + classes.size() + " class file(s)");
    }

    private void convertToDex() throws Exception {
        File dexFile = new File(buildDir, "classes.dex");
        File dxJar = new File(buildDir, "dx.jar");

        log(48, "Running DX converter...");

        try {
            runDx(dxJar, dexFile);
        } catch (Exception e) {
            log(50, "DX failed: " + e.getMessage());
            throw e;
        }

        if (!dexFile.exists()) {
            throw new Exception("DEX conversion failed - classes.dex not generated");
        }

        log(60, "DEX conversion complete. Size: " + (dexFile.length() / 1024) + " KB");
    }

    private void runDx(File dxJar, File dexFile) throws Exception {
        java.net.URLClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{dxJar.toURI().toURL()},
                null
        );

        Class<?> dxClass = loader.loadClass("com.android.dx.command.Main");
        java.lang.reflect.Method main = dxClass.getMethod("main", String[].class);

        String[] args = {
                "--dex",
                "--output=" + dexFile.getAbsolutePath(),
                classesDir.getAbsolutePath()
        };

        main.invoke(null, (Object) args);
        loader.close();
    }

    private File packageApk() throws Exception {
        File unsignedApk = new File(buildDir, "unsigned.apk");
        File dexFile = new File(buildDir, "classes.dex");

        log(68, "Creating APK package...");

        File manifest = (manifestFile != null && manifestFile.exists())
                ? manifestFile
                : generateDefaultManifest();

        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(unsignedApk))) {
            addToZip(zos, dexFile, "classes.dex");
            log(72, "Added classes.dex");

            addToZip(zos, manifest, "AndroidManifest.xml");
            log(75, "Added AndroidManifest.xml");

            byte[] minimalArsc = generateMinimalResourcesArsc(appName, packageName);
            ZipEntry arscEntry = new ZipEntry("resources.arsc");
            zos.putNextEntry(arscEntry);
            zos.write(minimalArsc);
            zos.closeEntry();
            log(78, "Added resources.arsc");

            addMinimalResources(zos, appName);
            log(82, "Added resources");
        }

        log(83, "APK package created: " + (unsignedApk.length() / 1024) + " KB");
        return unsignedApk;
    }

    private File signApk(File unsignedApk) throws Exception {
        log(87, "Generating signing key...");

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        X509Certificate cert = generateSelfSignedCert(keyPair, packageName);

        log(91, "Signing APK...");

        File signedApk = new File(outputDir, appName.replaceAll("[^a-zA-Z0-9]", "_") + ".apk");

        ApkSigner signer = new ApkSigner(privateKey, cert);
        signer.sign(unsignedApk, signedApk);

        log(97, "APK signed successfully!");
        return signedApk;
    }

    private File generateDefaultManifest() throws IOException {
        File manifest = new File(buildDir, "AndroidManifest.xml");
        String content = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\"\n" +
                "    package=\"" + packageName + "\">\n" +
                "    <application\n" +
                "        android:label=\"" + appName + "\">\n" +
                "        <activity android:name=\".MainActivity\" android:exported=\"true\">\n" +
                "            <intent-filter>\n" +
                "                <action android:name=\"android.intent.action.MAIN\" />\n" +
                "                <category android:name=\"android.intent.category.LAUNCHER\" />\n" +
                "            </intent-filter>\n" +
                "        </activity>\n" +
                "    </application>\n" +
                "</manifest>";
        writeFile(manifest, content);
        return manifest;
    }

    private byte[] generateMinimalResourcesArsc(String appName, String packageName) {
        return new byte[]{
                0x02, 0x00, 0x0C, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x00, 0x00
        };
    }

    private void addMinimalResources(ZipOutputStream zos, String appName) throws IOException {
        String stringsXml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
                "<resources>\n" +
                "    <string name=\"app_name\">" + appName + "</string>\n" +
                "</resources>";
        ZipEntry entry = new ZipEntry("res/values/strings.xml");
        zos.putNextEntry(entry);
        zos.write(stringsXml.getBytes("UTF-8"));
        zos.closeEntry();
    }

    private X509Certificate generateSelfSignedCert(KeyPair keyPair, String cn) throws Exception {
        Class<?> x509v3Class = Class.forName("org.bouncycastle.x509.X509V3CertificateGenerator");
        Object certGen = x509v3Class.newInstance();

        Class<?> x500Class = Class.forName("javax.security.auth.x500.X500Principal");
        Object principal = x500Class.getConstructor(String.class).newInstance("CN=" + cn + ", O=APKBuilder, C=US");

        x509v3Class.getMethod("setSerialNumber", BigInteger.class)
                .invoke(certGen, BigInteger.valueOf(System.currentTimeMillis()));
        x509v3Class.getMethod("setSubjectDN", Class.forName("org.bouncycastle.asn1.x509.X509Name"))
                .invoke(certGen, convertPrincipal(principal));
        x509v3Class.getMethod("setIssuerDN", Class.forName("org.bouncycastle.asn1.x509.X509Name"))
                .invoke(certGen, convertPrincipal(principal));
        x509v3Class.getMethod("setNotBefore", Date.class)
                .invoke(certGen, new Date(System.currentTimeMillis() - 86400000L));
        x509v3Class.getMethod("setNotAfter", Date.class)
                .invoke(certGen, new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000));
        x509v3Class.getMethod("setPublicKey", java.security.PublicKey.class)
                .invoke(certGen, keyPair.getPublic());
        x509v3Class.getMethod("setSignatureAlgorithm", String.class)
                .invoke(certGen, "SHA256WithRSAEncryption");

        return (X509Certificate) x509v3Class
                .getMethod("generate", java.security.PrivateKey.class)
                .invoke(certGen, keyPair.getPrivate());
    }

    private Object convertPrincipal(Object principal) throws Exception {
        Class<?> nameClass = Class.forName("org.bouncycastle.asn1.x509.X509Name");
        return nameClass.getConstructor(String.class)
                .newInstance(((javax.security.auth.x500.X500Principal) principal).getName());
    }

    private void log(int percent, String msg) {
        callback.onProgress(percent, msg);
    }

    private void extractAsset(String assetName, File dest) throws IOException {
        try (InputStream in = context.getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
        }
    }

    private void addToZip(ZipOutputStream zos, File file, String entryName) throws IOException {
        ZipEntry entry = new ZipEntry(entryName);
        zos.putNextEntry(entry);
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buf = new byte[4096];
            int len;
            while ((len = fis.read(buf)) > 0) {
                zos.write(buf, 0, len);
            }
        }
        zos.closeEntry();
    }

    private String readFile(File file) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        }
        return sb.toString();
    }

    private void writeFile(File file, String content) throws IOException {
        file.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes("UTF-8"));
        }
    }

    private List<File> listFiles(File dir, String ext) {
        List<File> result = new ArrayList<>();
        if (!dir.exists()) return result;
        File[] files = dir.listFiles();
        if (files == null) return result;
        for (File f : files) {
            if (f.isDirectory()) {
                result.addAll(listFiles(f, ext));
            } else if (f.getName().endsWith(ext)) {
                result.add(f);
            }
        }
        return result;
    }

    private String getMainClassName(String javaContent) {
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("public\\s+class\\s+(\\w+)")
                .matcher(javaContent);
        return m.find() ? m.group(1) : "MainActivity";
    }
}
