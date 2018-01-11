package de.neumann.quickencrypt;

import javax.crypto.*;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;

/**
 * Created by GN on 04.11.2016.
 */
public class EncryptionTool {

    public enum AESMode{
        AES_128(0x80),
        AES_192(0xC0),
        AES_256(0x100);

        private int keySize;

        AESMode(int size) {
            keySize = size;
        }

        public int getKeySize() {
            return keySize;
        }
    }

    /**
     * Folder name for the decrypted files.
     */
    private static final String DECODE_FOLDER = "decoded";

    /**
     * Folder name for the encrypted files.
     */
    private static final String ENCODE_FOLDER = "encoded";

    /**
     *  Number of iterations the AES-key  is created with.
     */
    private static final int ITERATIONS = 0x1000;

    /**
     *  Size of the vector used for padding. Is the default value of 16 bytes.
     */
    private static final int IV_SIZE = 0x10;

    /**
     *  AES-Mode to use for cryptography. Default is AES_128.
     */
    private AESMode mode = AESMode.AES_128;

    /**
     *  Keeps the vector for the padding, generated from password.
     */
    private final IvParameterSpec ivSpec;

    /**
     *  Keeps the key for cryptography, generated from password.
     */
    private final SecretKey secretKey;

    /**
     * Initiates an instance of a cryptography object, initializing necessary components.
     * @param encMode Version of AES to use.
     * @param password for en- and decrypting.
     */
    public EncryptionTool(AESMode encMode, String password) {
        mode = encMode;
        secretKey = createKey(password);
        ivSpec = new IvParameterSpec(hash128(password.getBytes()));
    }

    /**
     * Encrypts a file and saves the encrypted file in the same path under a new folder called encoded.
     * @param file to decrypt.
     * @return wether encryption was successful.
     */
    public boolean encrypt(File file) {
        try {

            File target = new File(file.getParent() + "\\" + ENCODE_FOLDER + "\\" + file.getName());

            if (!target.exists()) {
                Files.createDirectories(Paths.get(file.getParent() + "\\" + ENCODE_FOLDER));
                Files.createFile(Paths.get(target.getPath()));
            }

            if (encrypt(new FileInputStream(file), new FileOutputStream(target, false))) {
                return true;
            } else {
                return false;
            }

        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Decrypts a file and saves the decrypted file in the same folder under a new folder called decoded.
     * @param file to decrypt.
     * @return wether decryption was successful.
     */
    public boolean decrypt(File file) {
        try {
            File target = new File(file.getParent() + "\\" + DECODE_FOLDER + "\\" + file.getName());

            if (!target.exists()) {
                Files.createDirectories(Paths.get(file.getParent() + "\\" + DECODE_FOLDER));
                Files.createFile(Paths.get(target.getPath()));
            }

            if (decrypt(new FileInputStream(file), new FileOutputStream(target, false))) {
                return true;
            } else {
                return false;
            }
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Actual encryption process.
     * @param data Stream of data to encrypt.
     * @param output Stream where encrypted data is written to.
     * @return wether encryption was successful.
     */
    private boolean encrypt(final InputStream data, final OutputStream output) {
        int input;

        try {
            Cipher cipi = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipi.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            CipherOutputStream cos = new CipherOutputStream(output, cipi);

            while ((input = data.read()) != -1) {
                cos.write(input);
            }

            cos.flush();
            cos.close();
            output.flush();
            output.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Actual decryption process.
     * @param data Stream of data to decrypt.
     * @param output Stream where decrypted data is written to.
     * @return wether decryption was successful.
     */
    private boolean decrypt(final InputStream data, final OutputStream output) {
        int input;

        try {
            Cipher cipi = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipi.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);

            CipherOutputStream cos = new CipherOutputStream(output, cipi);

            while ((input = data.read()) != -1) {
                cos.write(input);
            }

            cos.flush();
            cos.close();
            output.flush();
            output.close();
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /**
     * Generates AES-Key from a specified password.
     * @param raw password.
     * @return generated key.
     */
    private SecretKey createKey(final String raw) {
        SecretKey result;

        byte[] salt = hash256(raw.getBytes());

        try {

            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

            KeySpec spec = new PBEKeySpec(raw.toCharArray(), salt, ITERATIONS, mode.getKeySize());

            SecretKey tmp = skf.generateSecret(spec);

            result = new SecretKeySpec(tmp.getEncoded(), "AES");

        } catch (Exception e) {
            e.printStackTrace();
            result = null;
        }

        return result;
    }

    /**
     * Creates a SHA-128 hash from a byte-array.
     * @param data input array that is to be hashed.
     * @return SHA-128 hash value of the input array.
     */
    public static byte[] hash128(byte[] data) {
        byte[] q = new byte[16];

        try {

            byte[] tmp;

            MessageDigest md =  MessageDigest.getInstance("SHA1");

            md.update(data);

            tmp = md.digest();

            System.arraycopy(tmp, 0, q, 0, IV_SIZE);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return q;
    }

    /**
     * Creates a SHA-256 hash from a given byte-array.
     * @param data input array that is to be hashed.
     * @return SHA-256 hash value of the input array.
     */
    public static byte[] hash256(byte[] data) {
        byte[] q = null;

        try {

            MessageDigest md =  MessageDigest.getInstance("SHA-256");

            md.update(data);

            q = md.digest();

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return q;
    }

}
