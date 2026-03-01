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
        extractAsset("android.zip", new File(buildDir, "android.jar"), 8);
        extractAsset("dx.zip", new File(buildDir, "dx.jar"), 12);
        extractAsset("janino.zip", new File(buildDir, "janino.jar"), 13);
        extractAsset("commons-compiler.zip", new File(buildDir, "commons-compiler.jar"), 14);
        log(15, "Environment ready.");
    }

    private void compileJava() throws Exception {
        File androidJar = new File(buildDir, "android.jar");
        File janinoJar = new File(buildDir, "janino.jar");
        File commonsJar = new File(buildDir, "commons-compiler.jar");

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

        // Use Janino compiler via reflection - works on Android ART
        java.net.URLClassLoader janinoLoader = new java.net.URLClassLoader(
                new java.net.URL[]{
                        commonsJar.toURI().toURL(),
                        janinoJar.toURI().toURL()
                },
                ClassLoader.getSystemClassLoader()
        );

        try {
            // Janino's JavaC compiler
            Class<?> compilerClass = janinoLoader.loadClass("org.codehaus.janino.JavaC");
            log(27, "Janino loaded: " + compilerClass.getName());

            Object compiler = compilerClass.newInstance();

            // Set classpath
            compilerClass.getMethod("setClassPath", String.class)
                    .invoke(compiler, androidJar.getAbsolutePath());

            // Set destination directory
            compilerClass.getMethod("setDestinationDirectory", String.class, boolean.class)
                    .invoke(compiler, classesDir.getAbsolutePath(), true);

            // Compile
            compilerClass.getMethod("compile", File[].class)
                    .invoke(compiler, new Object[]{new File[]{srcFile}});

            log(35, "Janino compilation done!");

        } catch (Exception e) {
            log(27, "Janino JavaC failed: " + e.getMessage() + ", trying compiler tool...");
            // Try alternative Janino API
            try {
                Class<?> toolClass = janinoLoader.loadClass("org.codehaus.janino.util.ClassFile");
                log(28, "Trying Compiler class...");
                Class<?> compClass = janinoLoader.loadClass("org.codehaus.janino.Compiler");
                Object comp = compClass.getConstructor(
                        File[].class, File.class, File.class, File.class, String.class
                ).newInstance(
                        new File[]{srcFile},
                        new File(androidJar.getAbsolutePath()),
                        null, classesDir, null
                );
                compClass.getMethod("compile").invoke(comp);
            } catch (Exception e2) {
                throw new Exception("Janino compilation failed: " + e.getMessage() + " / " + e2.getMessage());
            }
        } finally {
            janinoLoader.close();
        }

        List<File> classes = listFiles(classesDir, ".class");
        if (classes.isEmpty()) throw new Exception("No .class files generated");
        log(40, "Compiled " + classes.size() + " class(es)");
    }

    private void convertToDex() throws Exception {
        File dexFile = new File(buildDir, "classes.dex");
        File dxJar = new File(buildDir, "dx.jar");
        log(48, "Running DX...");
        java.net.URLClassLoader loader = new java.net.URLClassLoader(
                new java.net.URL[]{dxJar.toURI().toURL()}, null);
        Class<?> dxClass = loader.loadClass("com.android.dx.command.Main");
        String[] args = {"--dex", "--output=" + dexFile.getAbsolutePath(), classesDir.getAbsolutePath()};
        dxClass.getMethod("main", String[].class).invoke(null, (Object) args);
        loader.close();
        if (!dexFile.exists()) throw new Exception("DEX conversion failed");
        log(60, "DEX done: " + (dexFile.length()/1024) + " KB");
    }

    private File packageApk() throws Exception {
        File unsignedApk = new File(buildDir, "unsigned.apk");
        File dexFile = new File(buildDir, "classes.dex");
        log(68, "Packaging...");
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

    private void extractAsset(String assetName, File dest, int logPercent) throws IOException {
        log(logPercent, "Extracting " + assetName + "...");
        try (InputStream in = context.getAssets().open(assetName);
             FileOutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[8192]; int len;
            while ((len = in.read(buf)) > 0) out.write(buf, 0, len);
        }
        log(logPercent, "  -> " + dest.getName() + ": " + (dest.length()/1024) + " KB");
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
