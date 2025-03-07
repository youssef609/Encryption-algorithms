public interface StreamCipher {
    byte[] encrypt(byte[] plaintext);
    byte[] decrypt(byte[] cipherBytes);
    byte[] generateKey(int len);

}