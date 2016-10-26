package com.github.axet.androidlibrary.crypto;

import android.util.Base64;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

// http://www.bouncycastle.org/wiki/display/JA1/Elliptic+Curve+Key+Pair+Generation+and+Key+Factories
public class Bitcoin {
    public ECPrivateKey sec;
    public ECPublicKey pub;

    KeyFactory f;
    KeyPairGenerator g;
    ECGenParameterSpec ecGenSpec;

    // bouncycastle source
    static EllipticCurve secp256k1 = new EllipticCurve(
            new ECFieldFp(new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")),
            new BigInteger("0"),
            new BigInteger("7"));

    BigInteger order = new BigInteger("115792089237316195423570985008687907852837564279074904382605163141518161494337");
    ECPoint generator = new ECPoint(
            new BigInteger("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            new BigInteger("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
    ECParameterSpec spec = new ECParameterSpec(secp256k1, generator, order, 1);

    boolean noKey = false;
    int tagLength = 32;

    public static byte[] toBytes(BigInteger i) { // cut leading zeros
        byte[] out = new byte[i.bitLength() / 8 + (i.bitLength() % 8 > 0 ? 1 : 0)];
        byte[] buf = i.toByteArray();
        System.arraycopy(buf, buf.length - out.length, out, 0, out.length);
        return out;
    }

    public static byte[] toBytes(BigInteger i, int size) { // add leading zeros
        byte[] out = new byte[size];
        byte[] buf = i.toByteArray();
        int len = i.bitLength() / 8 + (i.bitLength() % 8 > 0 ? 1 : 0);
        int offset = buf.length - len;
        System.arraycopy(buf, offset, out, size - len, len);
        return out;
    }

    public static BigInteger fromBytes(byte[] buf) {
        return new BigInteger(concat(new byte[]{0}, buf));
    }

    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] b = new byte[b1.length + b2.length];
        System.arraycopy(b1, 0, b, 0, b1.length);
        System.arraycopy(b2, 0, b, b1.length, b2.length);
        return b;
    }

    public static byte[] concat(byte[]... bb) {
        int len = 0;
        for (byte[] b : bb)
            len += b.length;
        byte[] res = new byte[len];
        int offset = 0;
        for (byte[] b : bb) {
            System.arraycopy(b, 0, res, offset, b.length);
            offset += b.length;
        }
        return res;
    }

    public byte[] slice(byte[] b, int start, int end) {
        byte[] res = new byte[end - start];
        System.arraycopy(b, start, res, 0, res.length);
        return res;
    }

    public byte[] head(byte[] b, int len) {
        return slice(b, 0, len);
    }


    public static ECPoint mult(ECPoint P, BigInteger k) {
//        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
//        ECCurve c = spec.getCurve();
//        org.spongycastle.math.ec.ECPoint p = c.createPoint(P.getAffineX(), P.getAffineY());
//        org.spongycastle.math.ec.ECPoint pp = p.multiply(k).normalize();
//        return new ECPoint(pp.getXCoord().toBigInteger(), pp.getYCoord().toBigInteger());
        ECPointArthimetic d = new ECPointArthimetic(secp256k1, P.getAffineX(), P.getAffineY(), null);
        d = d.multiply(k);
        return new ECPoint(d.getX(), d.getY());
    }

    public byte[] getKEKM() {
        BigInteger bn = sec.getS();
        ECPoint w = pub.getW();
        byte[] buf = toBytes(mult(w, bn).getAffineX());
        byte[] b32 = head(buf, 32);
        return SHA512.digest(b32);
    }

    public static byte[] sha256hmac(byte[] key, byte[] data) throws Exception {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return sha256_HMAC.doFinal(data);
    }

    public Bitcoin() {
        try {
            f = KeyFactory.getInstance("EC", "BC");
            ecGenSpec = new ECGenParameterSpec("secp256k1");
            g = KeyPairGenerator.getInstance("EC", "BC");
            g.initialize(ecGenSpec, new SecureRandom());
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Bitcoin(BigInteger d) {
        this();
        loadSec(d);
        loadPub(sec);
    }

    public Bitcoin(String d) {
        this();
        loadSec(d);
        loadPub(sec);
    }

    public void generate() {
        java.security.KeyPair pair = g.generateKeyPair();
        this.sec = (ECPrivateKey) pair.getPrivate();
        this.pub = (ECPublicKey) pair.getPublic();
    }

    public byte[] getSecBuf() {
        return toBytes(sec.getS(), 32);
    }

    public String getSec() {
        return Base58.encode(getSecBuf());
    }

    public byte[] getPubBuf() {
        ECPoint w = pub.getW();
        byte[] a = toBytes(w.getAffineX(), 32);
        byte[] b = toBytes(w.getAffineY(), 32);
        byte[] type = new byte[]{0x04};
        return concat(type, a, b);
    }

    public String Base58CheckEncode(byte[] buf) {
        byte[] b = SHA256.digest(SHA256.digest(buf));
        byte[] t = head(b, 4);
        return Base58.encode(concat(buf, t));
    }

    public String getAddress() { // get public address
        RipeMD160 md160 = new RipeMD160();
        md160.update(SHA256.digest(getPubBuf()));
        byte[] md = md160.digest();
        byte[] addr = new byte[]{0x00};
        return Base58CheckEncode(concat(addr, md));
    }

    public String saveSec() {
        return Base58.encode(getSecBuf());
    }

    public String savePub() {
        return Base58.encode(getPubBuf());
    }

    public void loadSec64(String str) {
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decode(str, Base64.DEFAULT));
            sec = (ECPrivateKey) f.generatePrivate(spec);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void loadSec(String str) {
        byte[] buf = Base58.decode(str);
        byte[] x = slice(buf, 0, 32);
        loadSec(fromBytes(x));
    }

    public void loadSec(BigInteger d) {
        try {
            sec = (ECPrivateKey) f.generatePrivate(new ECPrivateKeySpec(d, spec));
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void loadPub64(String str) {
        try {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.decode(str, Base64.DEFAULT));
            pub = (ECPublicKey) f.generatePublic(spec);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void loadPub(ECPrivateKey key) {
        try {
            ECPoint p = mult(generator, key.getS());
            pub = (ECPublicKey) f.generatePublic(new ECPublicKeySpec(p, spec));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public void loadPub(String str) {
        try {
            byte[] buf = Base58.decode(str);
            byte[] x = slice(buf, 1, 33);
            byte[] y = slice(buf, 33, 65);
            ECPoint p = new ECPoint(fromBytes(x), fromBytes(y));
            pub = (ECPublicKey) f.generatePublic(new ECPublicKeySpec(p, spec));
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public void setNoKey(boolean noKey) {
        this.noKey = noKey;
    }

    public boolean isNoKey() {
        return noKey;
    }

    public void setTagLength(int tagLength) {
        this.tagLength = tagLength;
    }

    public int getTagLength() {
        return tagLength;
    }

    // bitcore-ecies javascript
    public String encrypt(String msg) {
        byte[] buf = msg.getBytes(Charset.defaultCharset());
        return Base64.encodeToString(encrypt(buf), Base64.DEFAULT);
    }

    public byte[] encrypt(byte[] buf) {
        try {
//            ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secp256k1");
//            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", "SC");
//            g.initialize(ecGenSpec, new SecureRandom());
//            Cipher ciper = Cipher.getInstance("ECIES/NONE/NOPADDING", "SC"); // ECIESwithAES-CBC
//            ciper.init(Cipher.ENCRYPT_MODE, pub);
            byte[] kEkM = getKEKM();
            byte[] kE = head(kEkM, 32);
            byte[] kM = slice(kEkM, 32, 64);

            byte[] sec = getSecBuf();
            byte[] pub = new byte[0];
            if (!noKey)
                pub = getPubBuf();
            byte[] keyIv = sha256hmac(sec, buf);
            byte[] ivbuf = head(keyIv, 16);
            Key outKey = new SecretKeySpec(kE, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, outKey, new IvParameterSpec(ivbuf));
            byte[] enc = cipher.doFinal(buf);
            byte[] enciv = concat(ivbuf, enc);
            byte[] d = sha256hmac(kM, enciv);
            if (tagLength < d.length) {
                d = head(d, tagLength);
            }
            return concat(pub, enciv, d);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // bitcore-ecies javascript
    public String decrypt(String msg) {
        byte[] buf = Base64.decode(msg.getBytes(Charset.defaultCharset()), Base64.DEFAULT);
        return new String(decrypt(buf), Charset.defaultCharset());
    }

    public byte[] decrypt(byte[] buf) {
        try {
//            Cipher cipher = Cipher.getInstance("ECIES/NONE/NOPADDING", "SC"); // ECIESwithAES-CBC
//            cipher.init(Cipher.DECRYPT_MODE, sec);
            byte[] kEkM = getKEKM();
            byte[] kE = head(kEkM, 32);
            byte[] kM = slice(kEkM, 32, 64);

            int offset = 0;

            byte[] pub = new byte[0];
            if (!noKey)
                pub = slice(buf, offset, offset + 65);
            offset += pub.length;

            byte[] enc = slice(buf, offset, buf.length - tagLength);
            offset += enc.length;

            byte[] d = slice(buf, offset, buf.length);

            byte[] d2 = sha256hmac(kM, enc);
            if (tagLength < d2.length)
                d2 = head(d2, tagLength);
            for (int i = 0; i < d2.length; i++) {
                if (d[i] != d2[i])
                    throw new RuntimeException("Invalid checksum");
            }
            byte[] ivbuf = head(enc, 128 / 8);
            byte[] ctbuf = slice(enc, ivbuf.length, enc.length);

            Key outKey = new SecretKeySpec(kE, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, outKey, new IvParameterSpec(ivbuf));
            return cipher.doFinal(ctbuf);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
