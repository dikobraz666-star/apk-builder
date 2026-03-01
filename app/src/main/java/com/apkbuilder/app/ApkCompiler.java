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
        log(15, "Environment ready.");
    }

    private void compileJava() throws Exception {
        File androidJar = new File(buildDir, "android.jar");

        // Prepare source file in proper package directory
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

        // Load ECJ DEX from APK assets using InMemoryDexClassLoader
        java.nio.ByteBuffer dexBuffer;
        try (java.util.zip.ZipFile apkZip = new java.util.zip.ZipFile(context.getPackageCodePath())) {
            java.util.zip.ZipEntry zipEntry = apkZip.getEntry("assets/ecj.zip");
            if (zipEntry == null) throw new Exception("assets/ecj.zip not found in APK");
            byte[] zipBytes;
            try (InputStream zipIn = apkZip.getInputStream(zipEntry)) {
                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                byte[] buf = new byte[8192]; int n;
                while ((n = zipIn.read(buf)) > 0) baos.write(buf, 0, n);
                zipBytes = baos.toByteArray();
            }
            // ecj.zip is a zip containing classes.dex
            try (java.util.zip.ZipInputStream innerZip = new java.util.zip.ZipInputStream(
                    new java.io.ByteArrayInputStream(zipBytes))) {
                java.util.zip.ZipEntry inner;
                byte[] dexBytes = null;
                while ((inner = innerZip.getNextEntry()) != null) {
                    if (inner.getName().endsWith(".dex")) {
                        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
                        byte[] buf = new byte[8192]; int n;
                        while ((n = innerZip.read(buf)) > 0) baos.write(buf, 0, n);
                        dexBytes = baos.toByteArray();
                        break;
                    }
                }
                if (dexBytes == null) throw new Exception("No .dex found inside ecj.zip");
                log(27, "Extracted ECJ DEX: " + dexBytes.length + " bytes");
                dexBuffer = java.nio.ByteBuffer.wrap(dexBytes);
            }
        }

        dalvik.system.InMemoryDexClassLoader ecjLoader = new dalvik.system.InMemoryDexClassLoader(
                dexBuffer,
                context.getClassLoader()
        );

        try {
            Class<?> ecjClass = ecjLoader.loadClass("org.eclipse.jdt.internal.compiler.batch.Main");
            log(28, "Found ECJ: " + ecjClass.getName());

            StringWriter outSw = new StringWriter();
            StringWriter errSw = new StringWriter();
            PrintWriter outPw = new PrintWriter(outSw);
            PrintWriter errPw = new PrintWriter(errSw);

            // Instantiate ECJ Main - try 3-arg constructor, then scan for fallback
            Object ecj = null;
            try {
                java.lang.reflect.Constructor<?> ctor = ecjClass.getConstructor(
                        PrintWriter.class, PrintWriter.class, boolean.class);
                ecj = ctor.newInstance(outPw, errPw, false);
                log(29, "ECJ: 3-arg constructor OK");
            } catch (NoSuchMethodException e) {
                // Scan constructors for one starting with (PrintWriter, PrintWriter, boolean, ...)
                for (java.lang.reflect.Constructor<?> c : ecjClass.getConstructors()) {
                    Class<?>[] pt = c.getParameterTypes();
                    if (pt.length >= 3
                            && pt[0] == PrintWriter.class
                            && pt[1] == PrintWriter.class
                            && pt[2] == boolean.class) {
                        Object[] args = new Object[pt.length];
                        args[0] = outPw;
                        args[1] = errPw;
                        args[2] = false;
                        // remaining args stay null / false
                        ecj = c.newInstance(args);
                        log(29, "ECJ: " + pt.length + "-arg constructor OK");
                        break;
                    }
                }
            }
            if (ecj == null) throw new Exception("Could not instantiate ECJ Main");

            // Compile command:
            // -source 8 -target 8 -bootclasspath <android.jar> -classpath <android.jar>
            // -d <classesDir> -nowarn <srcFile>
            String compileArgs =
                    "-source 8 -target 8 " +
                    "-bootclasspath " + androidJar.getAbsolutePath() + " " +
                    "-classpath " + androidJar.getAbsolutePath() + " " +
                    "-d " + classesDir.getAbsolutePath() + " " +
                    "-nowarn " +
                    srcFile.getAbsolutePath();

            log(30, "ECJ cmd: " + compileArgs);

            boolean success;
            try {
                // compile(String) — the most common entry point
                java.lang.reflect.Method m = ecjClass.getMethod("compile", String.class);
                success = (Boolean) m.invoke(ecj, compileArgs);
                log(35, "ECJ compile(String) => " + success);
            } catch (NoSuchMethodException e) {
                // compile(String[])
                java.lang.reflect.Method m = ecjClass.getMethod("compile", String[].class);
                success = (Boolean) m.invoke(ecj, (Object) compileArgs.split(" "));
                log(35, "ECJ compile(String[]) => " + success);
            }

            outPw.flush(); errPw.flush();
            String out = outSw.toString().trim();
            String err = errSw.toString().trim();
            if (!out.isEmpty()) log(35, "ECJ stdout: " + out);
            if (!err.isEmpty()) log(35, "ECJ stderr: " + err);

            if (!success) {
                throw new Exception("ECJ compilation failed:\n" + (err.isEmpty() ? out : err));
            }

        } catch (ClassNotFoundException e) {
            throw new Exception("ECJ class not found in DEX: " + e.getMessage());
        } catch (java.lang.reflect.InvocationTargetException e) {
            Throwable cause = e.getCause();
            throw new Exception("ECJ runtime error: " + (cause != null ? cause.toString() : e.toString()));
        }

        List<File> classes = listFiles(classesDir, ".class");
        if (classes.isEmpty()) throw new Exception("No .class files generated after ECJ compile");
        log(40, "Compiled " + classes.size() + " class(es)");
    }

    private void convertToDex() throws Exception {
        File dexFile = new File(buildDir, "classes.dex");
        File dxJar = new File(buildDir, "dx.jar");
        log(48, "Running DX...");

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
            String str = "<?xml version=\"1.0\" encoding=\"utf-8\"?><resources><string name=\"app_name\">"
                    + appName + "</string></resources>";
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
        Object name = Class.forName("org.bouncycastle.asn1.x509.X509Name")
                .getConstructor(String.class).newInstance("CN=" + cn);
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
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(content.getBytes("UTF-8"));
        }
    }

    private List<File> listFiles(File dir, String ext) {
        List<File> r = new ArrayList<>();
        if (!dir.exists()) return r;
        File[] files = dir.listFiles();
        if (files == null) return r;
        for (File f : files) {
            if (f.isDirectory()) r.addAll(listFiles(f, ext));
            else if (f.getName().endsWith(ext)) r.add(f);
        }
        return r;
    }

    private String getMainClassName(String src) {
        java.util.regex.Matcher m = java.util.regex.Pattern.compile("public\\s+class\\s+(\\w+)").matcher(src);
        return m.find() ? m.group(1) : "MainActivity";
    }
}
