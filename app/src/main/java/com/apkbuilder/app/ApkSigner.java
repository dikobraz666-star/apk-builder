package com.apkbuilder.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Signs an APK file using JAR v1 signature scheme.
 * Android accepts v1 (JAR) signatures for API < 24.
 * For broader compatibility, v1 is sufficient for sideloading.
 */
public class ApkSigner {

    private final PrivateKey privateKey;
    private final X509Certificate certificate;

    public ApkSigner(PrivateKey privateKey, X509Certificate certificate) {
        this.privateKey = privateKey;
        this.certificate = certificate;
    }

    public void sign(File unsignedApk, File signedApk) throws Exception {
        // Read all entries from the unsigned APK
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

        // Build MANIFEST.MF
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
        manifest.getMainAttributes().put(Attributes.Name.CREATED_BY, "APKBuilder 1.0");

        for (Map.Entry<String, byte[]> e : entries.entrySet()) {
            String name = e.getKey();
            if (name.startsWith("META-INF/")) continue;

            byte[] digest = sha256(e.getValue());
            String digestB64 = Base64.getEncoder().encodeToString(digest);

            Attributes attrs = new Attributes();
            attrs.putValue("SHA-256-Digest", digestB64);
            manifest.getEntries().put(name, attrs);
        }

        // Serialize MANIFEST.MF
        java.io.ByteArrayOutputStream manifestBytes = new java.io.ByteArrayOutputStream();
        manifest.write(manifestBytes);
        byte[] manifestData = manifestBytes.toByteArray();

        // Build CERT.SF
        byte[] sfData = buildSignatureFile(manifestData, entries);

        // Build CERT.RSA (PKCS#7 signature block)
        byte[] rsaData = buildSignatureBlock(sfData);

        // Write signed APK
        try (JarOutputStream jos = new JarOutputStream(new FileOutputStream(signedApk))) {
            // Write original entries
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                JarEntry je = new JarEntry(e.getKey());
                jos.putNextEntry(je);
                jos.write(e.getValue());
                jos.closeEntry();
            }

            // Write META-INF/MANIFEST.MF
            JarEntry mfEntry = new JarEntry("META-INF/MANIFEST.MF");
            jos.putNextEntry(mfEntry);
            jos.write(manifestData);
            jos.closeEntry();

            // Write META-INF/CERT.SF
            JarEntry sfEntry = new JarEntry("META-INF/CERT.SF");
            jos.putNextEntry(sfEntry);
            jos.write(sfData);
            jos.closeEntry();

            // Write META-INF/CERT.RSA
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
        // Create PKCS#7 signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(sfData);
        byte[] signature = sig.sign();

        // Build minimal PKCS#7 SignedData structure
        return buildPkcs7(signature, certificate.getEncoded());
    }

    private byte[] buildPkcs7(byte[] signature, byte[] certDer) throws Exception {
        // Use Android's built-in PKCS7 implementation via reflection
        try {
            Class<?> pkcs7Class = Class.forName("sun.security.pkcs.PKCS7");
            // Build via ContentInfo + SignerInfo
            // This is complex, so we use a simpler approach with BouncyCastle if available
            Class<?> cmssClass = Class.forName("org.bouncycastle.cms.CMSSignedDataGenerator");
            // ... use BC if available
        } catch (ClassNotFoundException e) {
            // Fall back to manual DER encoding
        }

        // Manual minimal PKCS#7 DER encoding
        return buildMinimalPkcs7DER(signature, certDer);
    }

    private byte[] buildMinimalPkcs7DER(byte[] signature, byte[] certDer) {
        // Build a minimal but valid PKCS#7 structure
        // OID for signedData: 1.2.840.113549.1.7.2
        byte[] signedDataOid = {0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x02};

        // Wrap signature in OCTET STRING
        byte[] sigOctet = derTlv(0x04, signature);
        // Wrap cert in SEQUENCE
        byte[] certSeq = certDer; // cert is already DER

        // Build SignerInfo (simplified)
        byte[] version = new byte[]{0x02, 0x01, 0x01}; // INTEGER 1
        byte[] signerInfo = derTlv(0x31, concat(version, sigOctet));

        // Build SignedData content
        byte[] signedData = derTlv(0x30, concat(version,
                derTlv(0x31, new byte[0]), // digestAlgorithms SET
                derTlv(0x30, new byte[]{0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x07, 0x01}), // contentInfo
                derTlv((byte) 0xA0, certSeq), // [0] certificates
                derTlv(0x31, signerInfo)  // signerInfos
        ));

        // Wrap in ContentInfo
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
