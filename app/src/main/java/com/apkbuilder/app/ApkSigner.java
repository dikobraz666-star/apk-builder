package com.apkbuilder.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Signs an APK file using JAR v1 signature scheme.
 */
public class ApkSigner {

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    public ApkSigner(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public void sign(File unsignedApk, File signedApk) throws Exception {
        Map<String, byte[]> entries = new LinkedHashMap<>();

        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(unsignedApk))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (!entry.isDirectory()) {
                    entries.put(entry.getName(), readBytes(zis));
                }
                zis.closeEntry();
            }
        }

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().putValue("Created-By", "APKBuilder 1.0");

        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            String name = e.getKey();
            if (name.startsWith("META-INF/")) continue;

            byte[] digest = sha256(e.getValue());
            String digestB64 = Base64.getEncoder().encodeToString(digest);

            Attributes attrs = new Attributes();
            attrs.putValue("SHA-256-Digest", digestB64);
            manifest.getEntries().put(name, attrs);
        }

        java.io.ByteArrayOutputStream manifestBytes = new java.io.ByteArrayOutputStream();
        manifest.write(manifestBytes);
        byte[] manifestData = manifestBytes.toByteArray();

        byte[] sfData = buildSignatureFile(manifestData, entries);
        byte[] rsaData = buildSignatureBlock(sfData);

        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(signedApk))) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                JarEntry je = new JarEntry(e.getKey());
                jos.putNextEntry(je);
                jos.write(e.getValue());
                jos.closeEntry();
            }

            JarEntry mfEntry = new JarEntry("META-INF/MANIFEST.MF");
            jos.putNextEntry(mfEntry);
            jos.write(manifestData);
            jos.closeEntry();

            JarEntry sfEntry = new JarEntry("META-INF/CERT.SF");
            jos.putNextEntry(sfEntry);
            jos.write(sfData);
            jos.closeEntry();

            JarEntry rsaEntry = new JarEntry("META-INF/CERT.RSA");
            jos.putNextEntry(rsaEntry);
            jos.write(rsaData);
            jos.closeEntry();
        }
    }

    private byte[] buildSignatureFile(byte[] manifestData, Map<String, byte[]> entries) throws Exception {
        StringBuilder sf = new StringBuilder();
        sf.append("Signature-Version: 1.0\r\n");
        sf.append("Created-By: APKBuilder 1.0\r\n");
        sf.append("SHA-256-Digest-Manifest: ")
                .append(Base64.getEncoder().encodeToString(sha256(manifestData)))
                .append("\r\n\r\n");

        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            String name = e.getKey();
            if (name.startsWith("META-INF/")) continue;
            byte[] digest = sha256(e.getValue());
            sf.append("Name: ").append(name).append("\r\n");
            sf.append("SHA-256-Digest: ")
                    .append(Base64.getEncoder().encodeToString(digest))
                    .append("\r\n\r\n");
        }

        return sf.toString().getBytes("UTF-8");
    }

    private byte[] buildSignatureBlock(byte[] sfData) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(sfData);
        byte[] signature = sig.sign();
        return buildMinimalPkcs7DER(signature, certificate.getEncoded());
    }

    private byte[] buildMinimalPkcs7DER(byte[] signature, byte[] certDer) {
        byte[] signedDataOid = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x02};

        byte[] sigOctet = derTlv(0x04, signature);
        byte[] certSeq = certDer;

        byte[] version = new byte[]{0x02, 0x01, 0x01};
        byte[] signerInfo = derTlv(0x31, concat(version, sigOctet));

        byte[] signedData = derTlv(0x30, concat(version,
                derTlv(0x31, new byte[0]),
                derTlv(0x30, new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x01}),
                derTlv((byte) 0xA0, certSeq),
                derTlv(0x31, signerInfo)
        ));

        byte[] contentInfo = derTlv(0x30, concat(
                derTlv(0x06, signedDataOid),
                derTlv((byte) 0xA0, signedData)
        ));

        return contentInfo;
    }

    private byte[] derTlv(int tag, byte[]... values) {
        int totalLen = 0;
        for (byte[] v : values) totalLen += v.length;

        byte[] lenBytes;
        if (totalLen < 128) {
            lenBytes = new byte[]{(byte) totalLen};
        } else if (totalLen < 256) {
            lenBytes = new byte[]{(byte) 0x81, (byte) totalLen};
        } else {
            lenBytes = new byte[]{(byte) 0x82, (byte) (totalLen >> 8), (byte) totalLen};
        }

        byte[] result = new byte[1 + lenBytes.length + totalLen];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        int offset = 1 + lenBytes.length;
        for (byte[] v : values) {
            System.arraycopy(v, 0, result, offset, v.length);
            offset += v.length;
        }
        return result;
    }

    private byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) total += a.length;
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] a : arrays) {
            System.arraycopy(a, 0, result, offset, a.length);
            offset += a.length;
        }
        return result;
    }

    private byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private byte[] readBytes(InputStream is) throws IOException {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int len;
        while ((len = is.read(buf)) > 0) {
            bos.write(buf, 0, len);
        }
        return bos.toByteArray();
    }
}
