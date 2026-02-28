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
        extractAssetIfNeeded("android.jar", 8);
        extractAssetIfNeeded("dx.jar", 12);
        extractAssetIfNeeded("ecj.jar", 14);
        log(15, "Environment ready.");
    }

    private void extractAssetIfNeeded(String name, int logPercent) throws IOException {
        File dest = new File(buildDir, name);
        if (!dest.exists()) {
            log(logPercent, "Extracting " + name + "...");
            extractAsset(name, dest);
        }
    }

    private void compileJava() throws Exception {
        File androidJar = new File(buildDir, "android.jar");
        File ecjJar = new File(buildDir, "ecj.jar");

        // List classes in ECJ jar for debugging
        log(21, "Scanning ecj.jar (" + (ecjJar.length()/1024) + " KB)...");
        List<String> compilerClasses = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(ecjJar))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName();
                if (name.endsWith(".class") && (name.contains("Main") || name.contains("Batch") || name.contains("batch"))) {
                    compilerClasses.add(name.replace("/", ".").replace(".class", ""));
                }
                zis.closeEntry();
            }
        }
        log(22, "Found " + compilerClasses.size() + " compiler classes");
        for (String cls : compilerClasses) {
            log(22, "  " + cls);
        }

        // Prepare source
        File srcDir = new File(buildDir, "src");
        String[] parts = packageName.split("\\.");
        File pkgDir = srcDir;
        for (String p : parts) pkgDir = new File(pkgDir, p);
        pkgDir.mkdirs();

        String javaContent = readFile(javaFile);
        if (!javaContent.startsWith("package " + packageName)) {
            javaContent = "package " + packageName + ";\n\n" +
                    javaContent.replaceFirst("^package [^;]+;\n?", "");
        }
        File srcFile = new File(pkgDir, getMainClassName(javaContent) + ".java");
        writeFile(srcFile, javaContent);
        log(25, "Compiling: " + srcFile.getName());

        java.net.URLClassLoader ecjLoader = new java.net.URLClassLoader(
                new java.net.URL[]{ecjJar.toURI().toURL()},
                ClassLoader.getSystemClassLoader()
        );

        try {
            StringWriter out = new StringWriter();
            StringWriter err = new StringWriter();
            PrintWriter pw1 = new PrintWriter(out);
            PrintWriter pw2 = new PrintWriter(err);
            boolean success = false;

            // Try every found class
            Exception lastEx = null;
            for (String cls : compilerClasses) {
                try {
                    Class<?> c = ecjLoader.loadClass(cls);
                    // Try static compile method
                    try {
                        String args = "-source 1.8 -target 1.8 -classpath \""
                                + androidJar.getAbsolutePath() + "\" -d \""
                                + classesDir.getAbsolutePath() + "\" \""
                                + srcFile.getAbsolutePath() + "\"";
                        success = (boolean) c.getMethod("compile",
                                String.class, PrintWriter.class, PrintWriter.class, Object.class)
                                .invoke(null, args, pw1, pw2, null);
                        log(35, "Compiled via " + cls + " (static)");
                        break;
                    } catch (Exception e1) {
                        // Try instance compile method
                        for (java.lang.reflect.Constructor<?> ctor : c.getConstructors()) {
                            int n = ctor.getParameterTypes().length;
                            try {
                                Object inst = null;
                                if (n == 3) inst = ctor.newInstance(pw1, pw2, false);
                                else if (n == 4) inst = ctor.newInstance(pw1, pw2, false, null);
                                else if (n == 5) inst = ctor.newInstance(pw1, pw2, false, null, null);
                                if (inst != null) {
                                    String[] argsArr = {"-source", "1.8", "-target", "1.8",
                                            "-classpath", androidJar.getAbsolutePath(),
                                            "-d", classesDir.getAbsolutePath(),
                                            srcFile.getAbsolutePath()};
                                    success = (boolean) c.getMethod("compile", String[].class)
                                            .invoke(inst, (Object) argsArr);
                                    log(35, "Compiled via " + cls + " (instance)");
                                    break;
                                }
                            } catch (Exception ignored) {}
                        }
                        if (success) break;
                    }
                } catch (Exception e) {
                    lastEx = e;
                }
            }

            if (!success) {
                String errors = err.toString();
                if (errors.isEmpty()) errors = out.toString();
                if (errors.isEmpty() && lastEx != null) errors = lastEx.getMessage();
                throw new Exception("Compilation failed:\n" + errors);
            }
        } finally {
            ecjLoader.close();
        }

        log(40, "Compilation successful!");
    }

    private void convertToDex() throws Exception {
        File dexFile = new File(buildDir, "classes.dex");
        File dxJar = new File(buildDir, "dx.jar");
        log(48, "Running DX converter...");
        java.net.URLClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{dxJar.toURI().toURL()}, null);
        Class<?> dxClass = loader.loadClass("com.android.dx.command.Main");
        String[] args = {"--dex", "--output=" + dexFile.getAbsolutePath(), classesDir.getAbsolutePath()};
        dxClass.getMethod("main", String[].class).invoke(null, (Object) args);
        loader.close();
        if (!dexFile.exists()) throw new Exception("DEX conversion failed");
        log(60, "DEX done: " + (dexFile.length() / 1024) + " KB");
    }

    private File packageApk() throws Exception {
        File unsignedApk = new File(buildDir, "unsigned.apk");
        File dexFile = new File(buildDir, "classes.dex");
        log(68, "Packaging APK...");
        File manifest = (manifestFile != null && manifestFile.exists())
                ? manifestFile : generateDefaultManifest();
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(unsignedApk))) {
            addToZip(zos, dexFile, "classes.dex");
            addToZip(zos, manifest, "AndroidManifest.xml");
            byte[] arsc = {0x02,0x00,0x0C,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00};
            zos.putNextEntry(new ZipEntry("resources.arsc"));
            zos.write(arsc);
            zos.closeEntry();
            String str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><resources><string name=\"app_name\">" + appName + "</string></resources>";
            zos.putNextEntry(new ZipEntry("res/values/strings.xml"));
            zos.write(str.getBytes("UTF-8"));
            zos.closeEntry();
        }
        return unsignedApk;
    }

    private File signApk(File unsignedApk) throws Exception {
        log(87, "Signing...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X509Certificate cert = generateSelfSignedCert(kp, packageName);
        File signedApk = new File(outputDir, appName.replaceAll("[^a-zA-Z0-9]", "_") + ".apk");
        new ApkSigner(kp.getPrivate(), cert).sign(unsignedApk, signedApk);
        return signedApk;
    }

    private File generateDefaultManifest() throws IOException {
        File f = new File(buildDir, "AndroidManifest.xml");
        writeFile(f, "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
                + "<manifest xmlns:android=\"http://schemas.android.com/apk/res/android\" package=\"" + packageName + "\">\n"
                + "<application android:label=\"" + appName + "\">\n"
                + "<activity android:name=\".MainActivity\" android:exported=\"true\">\n"
                + "<intent-filter><action android:name=\"android.intent.action.MAIN\"/>"
                + "<category android:name=\"android.intent.category.LAUNCHER\"/></intent-filter>\n"
                + "</activity></application></manifest>");
        return f;
    }

    private X509Certificate generateSelfSignedCert(KeyPair kp, String cn) throws Exception {
        Class<?> x509 = Class.forName("org.bouncycastle.x509.X509V3CertificateGenerator");
        Object gen = x509.newInstance();
        Object prin = Class.forName("javax.security.auth.x500.X500Principal").getConstructor(String.class).newInstance("CN=" + cn);
        Object name = Class.forName("org.bouncycastle.asn1.x509.X509Name").getConstructor(String.class).newInstance("CN=" + cn);
        x509.getMethod("setSerialNumber", BigInteger.class).invoke(gen, BigInteger.valueOf(System.currentTimeMillis()));
        x509.getMethod("setSubjectDN", Class.forName("org.bouncycastle.asn1.x509.X509Name")).invoke(gen, name);
        x509.getMethod("setIssuerDN", Class.forName("org.bouncycastle.asn1.x509.X509Name")).invoke(gen, name);
        x509.getMethod("setNotBefore", Date.class).invoke(gen, new Date(System.currentTimeMillis() - 86400000L));
        x509.getMethod("setNotAfter", Date.class).invoke(gen, new Date(System.currentTimeMillis() + 365L*24*60*60*1000));
        x509.getMethod("setPublicKey", java.security.PublicKey.class).invoke(gen, kp.getPublic());
        x509.getMethod("setSignatureAlgorithm", String.class).invoke(gen, "SHA256WithRSAEncryption");
        return (X509Certificate) x509.getMethod("generate", java.security.PrivateKey.class).invoke(gen, kp.getPrivate());
    }

    private void log(int p, String m) { callback.onProgress(p, m); }

    private void extractAsset(String name, File dest) throws IOException {
        try (InputStream in = context.getAssets().open(name);
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192]; int len;
            while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
        }
    }

    private void addToZip(ZipOutputStream zos, File f, String name) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        try (FileInputStream fis = new FileInputStream(f)) {
            byte[] buf = new byte[4096]; int len;
            while ((len = fis.read(buf)) > 0) zos.write(buf, 0, len);
        }
        zos.closeEntry();
    }

    private String readFile(File f) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (java.io.BufferedReader r = new java.io.BufferedReader(new java.io.FileReader(f))) {
            String line; while ((line = r.readLine()) != null) sb.append(line).append('\n');
        }
        return sb.toString();
    }

    private void writeFile(File f, String content) throws IOException {
        f.getParentFile().mkdirs();
        try (FileOutputStream fos = new FileOutputStream(f)) { fos.write(content.getBytes("UTF-8")); }
    }

    private List<File> listFiles(File dir, String ext) {
        List<File> r = new ArrayList<>();
        if (!dir.exists()) return r;
        File[] files = dir.listFiles();
        if (files == null) return r;
        for (File f : files) { if (f.isDirectory()) r.addAll(listFiles(f, ext)); else if (f.getName().endsWith(ext)) r.add(f); }
        return r;
    }

    private String getMainClassName(String src) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("public\\s+class\\s+(\\w+)").matcher(src);
        return m.find() ? m.group(1) : "MainActivity";
    }
}
