import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

class OpenSslAes {

    /** OpenSSL's magic initial bytes. */
    private static final String SALTED_STR = "Salted__";
    private static final byte[] SALTED_MAGIC = SALTED_STR.getBytes(US_ASCII);

    static String encrypt(String password, String saltStr, String clearText) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        final byte[] pass = password.getBytes(US_ASCII);//hexStringToByteArray(password);
        final byte[] salt = hexStringToByteArray(saltStr);//saltStr.getBytes(US_ASCII);
        final byte[] inBytes = clearText.getBytes(UTF_8);

        final byte[] passAndSalt = array_concat(pass, salt);
        byte[] hash = new byte[0];
        byte[] keyAndIv = new byte[0];
        for (int i = 0; i < 3 && keyAndIv.length < 48; i++) {
            final byte[] hashData = array_concat(hash, passAndSalt);
            final MessageDigest md = MessageDigest.getInstance("MD5");
            hash = md.digest(hashData);
            keyAndIv = array_concat(keyAndIv, hash);
        }

        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, 32);
        final byte[] iv = Arrays.copyOfRange(keyAndIv, 32, 48);

        System.out.println("key : " + bytesToHex(keyValue));
        System.out.println("iv : " + bytesToHex(iv));
        final SecretKeySpec key = new SecretKeySpec(keyValue, "AES");

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] data = cipher.doFinal(inBytes);
        data =  array_concat(array_concat(SALTED_MAGIC, salt), data);
        return Base64.getEncoder().encodeToString( data );
    }

    static String decrypt(String password, String source) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException, InvalidKeyException {
        final byte[] pass = password.getBytes(US_ASCII);

        final byte[] inBytes = Base64.getDecoder().decode(source);

        final byte[] shouldBeMagic = Arrays.copyOfRange(inBytes, 0, SALTED_MAGIC.length);
        if (!Arrays.equals(shouldBeMagic, SALTED_MAGIC)) {
            throw new IllegalArgumentException("Initial bytes from input do not match OpenSSL SALTED_MAGIC salt value.");
        }

        final byte[] salt = Arrays.copyOfRange(inBytes, SALTED_MAGIC.length, SALTED_MAGIC.length + 8);

        final byte[] passAndSalt = array_concat(pass, salt);

        byte[] hash = new byte[0];
        byte[] keyAndIv = new byte[0];
        for (int i = 0; i < 3 && keyAndIv.length < 48; i++) {
            final byte[] hashData = array_concat(hash, passAndSalt);
            final MessageDigest md = MessageDigest.getInstance("MD5");
            hash = md.digest(hashData);
            keyAndIv = array_concat(keyAndIv, hash);
        }

        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, 32);
        final SecretKeySpec key = new SecretKeySpec(keyValue, "AES");

        final byte[] iv = Arrays.copyOfRange(keyAndIv, 32, 48);

        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] clear = cipher.doFinal(inBytes, 16, inBytes.length - 16);
        return new String(clear, UTF_8);
    }


    private static byte[] array_concat(final byte[] a, final byte[] b) {
        final byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
