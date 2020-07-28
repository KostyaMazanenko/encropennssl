import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Enter password in hex:");
        String key = scanner.nextLine();

        System.out.println("Enter salt in hex:");
        String iv = scanner.nextLine();

        System.out.println("Enter text to encrypt:");
        String text = scanner.nextLine();

//        key = addToKey(key);
//        iv = addToIv(iv);
//        text = addToText(text);

        String encryptedText = "";

        try {
            encryptedText = encrypt(key, iv, text);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException | InvalidKeyException e) {
            e.printStackTrace();
        }

        System.out.println("result: " + encryptedText);
    }

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

//    public static byte[] hexStringToByteArray(String s) {
//        int len = s.length();
//        byte[] data = new byte[len / 2];
//        for (int i = 0; i < len; i += 2) {
//            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
//                    + Character.digit(s.charAt(i+1), 16));
//        }
//        return data;
//    }
}
