import java.util.Arrays;
import java.util.Scanner;

public class AES {

    private static final int BLOCK_SIZE = 16;
    private static final int NUM_ROUNDS = 10;
    private static final int KEY_SIZE = 16; // 128-bit key

    private static final int[] S_BOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    
    private static final int[] INV_S_BOX = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
    };
    
        // Key schedule
        private static byte[][] generateSubKeys(byte[] key) {
            byte[][] subKeys = new byte[11][BLOCK_SIZE];
            System.arraycopy(key, 0, subKeys[0], 0, BLOCK_SIZE);
    
            for (int round = 1; round <= NUM_ROUNDS; round++) {
                byte[] previousKey = subKeys[round - 1];
                byte[] roundKey = new byte[BLOCK_SIZE];
    
                // Word rotation
                byte[] rotatedWord = rotateWord(Arrays.copyOfRange(previousKey, 12, 16));
    
                // Word substitution
                for (int i = 0; i < rotatedWord.length; i++) {
                    rotatedWord[i] = substituteByte(rotatedWord[i]);
                }
    
                // XOR with round constant
                rotatedWord[0] ^= getRoundConstant(round);
    
                // Generate subkey
                for (int i = 0; i < 4; i++) {
                    int offset = i * 4;
                    for (int j = 0; j < 4; j++) {
                        if (i == 0) {
                            roundKey[offset + j] = (byte) (previousKey[offset + j] ^ rotatedWord[j]);
                        } else {
                            roundKey[offset + j] = (byte) (previousKey[offset + j] ^ roundKey[offset + j - 4]);
                        }
                    }
                }
                subKeys[round] = roundKey;
            }
    
            return subKeys;
        }
    
        // Rotate the word (4 bytes)
        private static byte[] rotateWord(byte[] word) {
            return new byte[]{word[1], word[2], word[3], word[0]};
        }
    
        // Substitute byte using the AES S-box
        private static byte substituteByte(byte b) {
            return (byte) S_BOX[b & 0xFF];
        }
    
        // Inverse substitute byte using the AES inverse S-box
        private static byte inverseSubstituteByte(byte b) {
            return (byte) INV_S_BOX[b & 0xFF];
        }
    
        // Get round constant with real implementation
        private static byte getRoundConstant(int round) {
            byte rcon = 1;
            for (int i = 1; i < round; i++) {
                rcon = (byte) ((rcon << 1) ^ ((rcon & 0x80) != 0 ? 0x1B : 0));
            }
            return rcon;
        }
    
        // Encryption process
        private static byte[] encrypt(byte[] plaintext, byte[][] subKeys) {
            byte[] state = Arrays.copyOf(plaintext, plaintext.length);
    
            // Initial key addition
            xorStateWithKey(state, subKeys[0]);
    
            for (int round = 1; round <= NUM_ROUNDS; round++) {
                // Byte substitution
                for (int i = 0; i < state.length; i++) {
                    state[i] = substituteByte(state[i]);
                }
    
                // Shift rows
                state = shiftRows(state);
    
                // Mix columns (not in the last round)
                if (round < NUM_ROUNDS) {
                    state = mixColumns(state);
                }
    
                // Add round key
                xorStateWithKey(state, subKeys[round]);
            }
    
            return state;
        }
    
        // Decryption process
        private static byte[] decrypt(byte[] ciphertext, byte[][] subKeys) {
            byte[] state = Arrays.copyOf(ciphertext, ciphertext.length);
    
            // Initial key addition
            xorStateWithKey(state, subKeys[NUM_ROUNDS]);
    
            for (int round = NUM_ROUNDS - 1; round >= 0; round--) {
                // Inverse Shift rows
                state = inverseShiftRows(state);
    
                // Inverse Byte substitution
                for (int i = 0; i < state.length; i++) {
                    state[i] = inverseSubstituteByte(state[i]);
                }
    
                // Add round key
                xorStateWithKey(state, subKeys[round]);
    
                // Inverse Mix columns (not in the first round)
                if (round > 0) {
                    state = inverseMixColumns(state);
                }
            }
    
            return state;
        }
    
        // XOR the state with a round key
        private static void xorStateWithKey(byte[] state, byte[] key) {
            for (int i = 0; i < state.length; i++) {
                state[i] ^= key[i];
            }
        }
    
        // Shift rows implementation
        private static byte[] shiftRows(byte[] state) {
            byte[] shiftedState = new byte[BLOCK_SIZE];
    
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    shiftedState[i * 4 + j] = state[i * 4 + (j + i) % 4];
                }
            }
    
            return shiftedState;
        }
    
        // Inverse Shift rows implementation
        private static byte[] inverseShiftRows(byte[] state) {
            byte[] shiftedState = new byte[BLOCK_SIZE];
    
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    shiftedState[i * 4 + j] = state[i * 4 + (j - i + 4) % 4];
                }
            }
    
            return shiftedState;
        }
    
        // Mix columns implementation
        private static byte[] mixColumns(byte[] state) {
            byte[] mixedState = new byte[BLOCK_SIZE];
            for (int i = 0; i < 4; i++) {
                int base = i * 4;
                mixedState[base] = (byte) (galoisMultiply(state[base], 2) ^ galoisMultiply(state[base + 1], 3) ^ state[base + 2] ^ state[base + 3]);
                mixedState[base + 1] = (byte) (state[base] ^ galoisMultiply(state[base + 1], 2) ^ galoisMultiply(state[base + 2], 3) ^ state[base + 3]);
                mixedState[base + 2] = (byte) (state[base] ^ state[base + 1] ^ galoisMultiply(state[base + 2], 2) ^ galoisMultiply(state[base + 3], 3));
                mixedState[base + 3] = (byte) (galoisMultiply(state[base], 3) ^ state[base + 1] ^ state[base + 2] ^ galoisMultiply(state[base + 3], 2));
            }
            return mixedState;
        }
    
        // Inverse Mix columns implementation
        private static byte[] inverseMixColumns(byte[] state) {
            byte[] mixedState = new byte[BLOCK_SIZE];
            for (int i = 0; i < 4; i++) {
                int base = i * 4;
                mixedState[base] = (byte) (galoisMultiply(state[base], 14) ^ galoisMultiply(state[base + 1], 11) ^ galoisMultiply(state[base + 2], 13) ^ galoisMultiply(state[base + 3], 9));
                mixedState[base + 1] = (byte) (galoisMultiply(state[base], 9) ^ galoisMultiply(state[base + 1], 14) ^ galoisMultiply(state[base + 2], 11) ^ galoisMultiply(state[base + 3], 13));
                mixedState[base + 2] = (byte) (galoisMultiply(state[base], 13) ^ galoisMultiply(state[base + 1], 9) ^ galoisMultiply(state[base + 2], 14) ^ galoisMultiply(state[base + 3], 11));
                mixedState[base + 3] = (byte) (galoisMultiply(state[base], 11) ^ galoisMultiply(state[base + 1], 13) ^ galoisMultiply(state[base + 2], 9) ^ galoisMultiply(state[base + 3], 14));
            }
            return mixedState;
        }
    
        // Real Galois field multiplication
        private static byte galoisMultiply(byte a, int b) {
            byte result = 0;
            for (int i = 0; i < 8; i++) {
                if ((b & (1 << i)) != 0) {
                    result ^= a;
                }
                a = (byte) ((a << 1) ^ ((a & 0x80) != 0 ? 0x1B : 0));
            }
            return result;
        }
    
        public static void main(String[] args) {
            Scanner scanner = new Scanner(System.in);
            try {
                // Input plaintext
                System.out.println("Enter plaintext (16 characters):");
                String plaintext = scanner.nextLine();
                if (plaintext.length() != BLOCK_SIZE) {
                    throw new IllegalArgumentException("Plaintext must be exactly 16 characters long.");
                }
    
                // Input key
                System.out.println("Enter key (16 characters):");
                String keyInput = scanner.nextLine();
                if (keyInput.length() != KEY_SIZE) {
                    throw new IllegalArgumentException("Key must be exactly 16 characters long.");
                }
    
                byte[] key = keyInput.getBytes();
                byte[][] subKeys = generateSubKeys(key);
    
                // Encrypt
                byte[] encrypted = encrypt(plaintext.getBytes(), subKeys);
    
                // Display encrypted text in hexadecimal
                System.out.print("Encrypted (Hex): ");
                for (byte b : encrypted) {
                    System.out.printf("%02X ", b);
                }
                System.out.println();
    
                // Display encrypted text as characters
                System.out.println("Encrypted (Characters): " + new String(encrypted));
    
                // Decrypt
                byte[] decrypted = decrypt(encrypted, subKeys);
    
                // Display decrypted text
                System.out.println("Decrypted Text: " + new String(decrypted));
    
            } catch (Exception e) {
                System.err.println("Error: " + e.getMessage());
            } finally {
                scanner.close();
            }
        }
    }
    
  /*test data : 
    Plaintext: ABCDEFGHIJKLMNOP
     Key: 1234567890ABCDEF 
 
   */
