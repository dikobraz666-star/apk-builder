package com.apkbuilder.app;

import android.content.Context;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
        // Copy janino.dex to trusted (non-writable) location required by Android 10+
        File trustedDir = context.getNoBackupFilesDir();
        trustedDir.mkdirs();
        extractAsset("janino.zip", new File(trustedDir, "janino.dex"), 14);
        log(15, "Environment ready. janino=" + (new File(trustedDir,"janino.dex").length()/1024) + "KB");
    }

    private void compileJava() throws Exception {
        File androidJar = new File(buildDir, "android.jar");
        File janinoDex = new File(context.getNoBackupFilesDir(), "janino.dex");

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

        // Load Janino DEX directly from APK using InMemoryDexClassLoader (Android 8+)
        // janino.zip is a zip containing classes.dex - extract the inner DEX bytes
        java.nio.ByteBuffer dexBuffer;
        try (java.util.zip.ZipFile apkZip = new java.util.zip.ZipFile(context.getPackageCodePath())) {
            java.util.zip.ZipEntry zipEntry = apkZip.getEntry("assets/janino.zip");
            if (zipEntry == null) throw new Exception("assets/janino.zip not found in APK");
            // janino.zip is itself a zip containing classes.dex
            byte[] zipBytes;
            try (InputStream zipIn = apkZip.getInputStream(zipEntry)) {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buf2 = new byte[8192]; int n2;
                while ((n2 = zipIn.read(buf2)) > 0) baos.write(buf2, 0, n2);
                zipBytes = baos.toByteArray();
            }
            // Now read classes.dex from inside janino.zip
            try (java.util.zip.ZipInputStream innerZip = new java.util.zip.ZipInputStream(
                    new java.io.ByteArrayInputStream(zipBytes))) {
                java.util.zip.ZipEntry inner;
                byte[] dexBytes = null;
                while ((inner = innerZip.getNextEntry()) != null) {
                    if (inner.getName().endsWith(".dex")) {
                        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                        byte[] buf2 = new byte[8192]; int n2;
                        while ((n2 = innerZip.read(buf2)) > 0) baos.write(buf2, 0, n2);
                        dexBytes = baos.toByteArray();
                        break;
                    }
                }
                if (dexBytes == null) throw new Exception("No .dex found inside janino.zip");
                log(27, "Extracted inner DEX: " + dexBytes.length + " bytes");
                dexBuffer = java.nio.ByteBuffer.wrap(dexBytes);
            }
        }
        log(27, "Loaded janino DEX from APK: " + dexBuffer.capacity() + " bytes");

        dalvik.system.InMemoryDexClassLoader janinoLoader = new dalvik.system.InMemoryDexClassLoader(
                dexBuffer,
                context.getClassLoader()
        );

        try {
            // Try different Janino compiler class names
            Class<?> compilerClass = null;
            String[] classNames = {
                "org.codehaus.janino.Compiler",
                "org.codehaus.janino.JavaC",
                "org.codehaus.commons.compiler.jdk.JavaSourceClassLoader",
                "org.codehaus.janino.SimpleCompiler"
            };
            for (String cn : classNames) {
                try { compilerClass = janinoLoader.loadClass(cn); log(27, "Found: " + cn); break; }
                catch (ClassNotFoundException ignored) { log(27, "Not found: " + cn); }
            }
            if (compilerClass == null) throw new Exception("No Janino compiler class found in DEX");

            String name = compilerClass.getName();
            if (name.equals("org.codehaus.janino.Compiler")) {
                // Log all available constructors
                java.lang.reflect.Constructor<?>[] ctors = compilerClass.getConstructors();
                log(28, "Compiler has " + ctors.length + " constructors:");
                for (java.lang.reflect.Constructor<?> c : ctors) {
                    log(28, "  " + c.toString());
                }
                // Try the first constructor that matches
                try {
                    Object compiler = ctors[0].newInstance(
                        new File[]{srcFile}, classesDir, srcFile.getParentFile(), androidJar, null
                    );
                    compilerClass.getMethod("compile").invoke(compiler);
                } catch (java.lang.reflect.InvocationTargetException ite) {
                    Throwable cause = ite.getCause();
                    throw new Exception("Compiler inner error: " + (cause != null ? cause.toString() : ite.toString()));
                }
            } else if (name.equals("org.codehaus.janino.SimpleCompiler")) {
                Object compiler = compilerClass.newInstance();
                compilerClass.getMethod("cook", java.io.Reader.class)
                    .invoke(compiler, new java.io.FileReader(srcFile));
            } else {
                Object compiler = compilerClass.newInstance();
                try { compilerClass.getMethod("setClassPath", String.class).invoke(compiler, androidJar.getAbsolutePath()); } catch(Exception ignored){}
                try { compilerClass.getMethod("setDestinationDirectory", String.class, boolean.class).invoke(compiler, classesDir.getAbsolutePath(), true); } catch(Exception ignored){}
                compilerClass.getMethod("compile", File[].class).invoke(compiler, new Object[]{new File[]{srcFile}});
            }
            log(35, "Compilation successful!");
        } catch (Exception e) {
            throw new Exception("Janino compile error: " + e.getMessage());
        }

        List<File> classes = listFiles(classesDir, ".class");
        if (classes.isEmpty()) throw new Exception("No .class files generated");
        log(40, "Compiled " + classes.size() + " class(es)");
    }

    private void convertToDex() throws Exception {
        File dexFile = new File(buildDir, "classes.dex");
        File dxJar = new File(buildDir, "dx.jar");
        log(48, "Running DX...");

        // DX also needs to run as DEX on Android
        // dx.jar is JVM bytecode - we need to run it differently
        // Use a shell command approach
        File dxDex = new File(buildDir, "dx.dex");
        // dx.jar is already extracted, try loading it
        File dexOptDir = new File(buildDir, "dexopt2");
        dexOptDir.mkdirs();

        try {
            dalvik.system.DexClassLoader dxLoader = new dalvik.system.DexClassLoader(
                    dxJar.getAbsolutePath(),
                    dexOptDir.getAbsolutePath(),
                    null,
                    ClassLoader.getSystemClassLoader()
            );
            Class<?> dxClass = dxLoader.loadClass("com.android.dx.command.Main");
            String[] args = {"--dex", "--output=" + dexFile.getAbsolutePath(), classesDir.getAbsolutePath()};
            dxClass.getMethod("main", String[].class).invoke(null, (Object) args);
        } catch (Exception e) {
            throw new Exception("DX error: " + e.getMessage());
        }

        if (!dexFile.exists()) throw new Exception("DEX conversion failed - no output file");
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
