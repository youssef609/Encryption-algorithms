import java.util.HashSet;
import java.util.Set;

public class LFSR implements StreamCipher {
    private static int[] defaultPolynom = {24, 4, 3, 1};
    private int[] polinom; //represents the indices of terms that appear in the polynomial used for feedback.
    protected long register;
    private long currRegister;
    private long mask;  //used to limit the bit-length of the register, ensuring the bits stay within the polynomial degree.

    public LFSR(long initRegister, int[] polynom) {
        this.register = initRegister;
        this.polinom = polynom;
        generateMask(); // mask ensures the register length matches the polynomial’s degree.
    }

    public LFSR(String initRegister, int[] polynom) {
        this.polinom = polynom;
        if (initRegister.length() > polinom[0]) {
            throw new IllegalArgumentException("Register length exceeds polynomial degree");
        }
        register = Long.parseLong(initRegister, 2);
        generateMask();
    }

    public LFSR(String initRegister) {
        this(initRegister, defaultPolynom);
    }

    private void generateMask() {
        mask = (1L << polinom[0]) - 1;
    }
        //retrieves the bit at a specific position within the register by right-shifting and applying an AND operation.
    private byte getBitAtPos(int pos) {
        return (byte) ((currRegister >> (pos - 1)) & 1);
    }
     //next bit by performing XOR operations on the bits specified by polinom. 
     //It then updates the register by shifting left and inserting the new bit at the end.
    private byte nextBit() {
        byte newBit = getBitAtPos(polinom[0]);
        for (int i = 1; i < polinom.length; i++) {
            newBit ^= getBitAtPos(polinom[i]);
        }
        currRegister = ((currRegister << 1) & mask) | newBit;
        return newBit;
    }
    //generates a key of specified length len by calling nextBit to get each bit

    @Override
    public byte[] generateKey(int len) {
        currRegister = register;
        byte[] key = new byte[len];
        for (int i = 0; i < len * 8; i++) {
            int byteIndex = i / 8;
            int bitIndex = 7 - (i % 8);
            key[byteIndex] |= (nextBit() << bitIndex);
            printFlipFlopState(i + 1, key[byteIndex]);
        }
        return key;
    }

    private void printFlipFlopState(int clockCycle, byte keyBit) {
        System.out.printf("Clock %2d | Register: %s | Key Bit: %d\n",
                clockCycle, Long.toBinaryString(currRegister), keyBit & 1);
    }
    

    @Override
    public byte[] encrypt(byte[] plainBytes) {
        byte[] key = generateKey(plainBytes.length);
        byte[] cipherBytes = new byte[plainBytes.length];
        for (int i = 0; i < plainBytes.length; i++) {
            cipherBytes[i] = (byte) (plainBytes[i] ^ key[i]);
        }
        System.out.println("Encrypted Binary: " + keyToStr(cipherBytes, cipherBytes.length));
        return cipherBytes;
    }

    @Override
    public byte[] decrypt(byte[] cipherBytes) {
        return encrypt(cipherBytes);
    }

    public static String keyToStr(byte[] key, int bytesCount) {
        StringBuilder strKey = new StringBuilder();
        for (int i = 0; i < bytesCount; i++) {
            String binarByte = String.format("%8s", Integer.toBinaryString(key[i] & 0xFF)).replace(' ', '0');
            strKey.append(binarByte);
        }
        return strKey.toString();
    }
    private int polynomialMod(int value, int[] poly) {
        int modValue = value;
        int polyDegree = poly[0];
        
        for (int i = Integer.highestOneBit(value); i >= (1 << polyDegree); i >>= 1) {
            if ((modValue & i) != 0) {
                modValue ^= shiftPoly(poly, i);
            }
        }
        return modValue;
    }

       // Shifts polynomial
       private int shiftPoly(int[] poly, int shift) {
        int shifted = 0;
        for (int p : poly) {
            shifted |= (1 << (shift - p));
        }
        return shifted;
    }


     public boolean isPrimitive() {
        int degree = polinom[0];
        int period = (1 << degree) - 1;
        
        if (!isIrreducible()) return false; // Must be irreducible to be primitive

        Set<Integer> seenPowers = new HashSet<>();
        int value = 1;
        for (int i = 0; i < period; i++) {
            value = polynomialMod(value, polinom);
            if (!seenPowers.add(value)) {
                return false;
            }
        }
        return seenPowers.size() == period;
    }

    public boolean isIrreducible() {
        int degree = polinom[0];
        int fieldSize = (1 << degree) - 1;

        // Check divisibility by lower degree polynomials
        for (int i = 1; i <= degree / 2; i++) {
            int testPoly = (1 << i) + 1; // Creating polynomial x^i + 1
            int[] testPolyArray = new int[] { i, 0 }; // Represent as {x^i, x^0}
            if (polynomialMod(fieldSize, testPolyArray) == 0) {
                return false; // Polynomial is reducible
            }
        }
        return true;
    }
    

    public void printPolynomialProperties() {
        System.out.println("Polynomial Properties:");
        System.out.println("Is Irreducible? " + (isIrreducible() ? "Yes" : "No"));
        System.out.println("Is Primitive? " + (isPrimitive() ? "Yes" : "No"));
    }

    public static void main(String[] args) {
        // Example Usage:
        String message = "youssef";
        int m = 9;
        int[] polynom = {4, 3, 1};
        String initRegister = "1011"; // Example initialization vector

        LFSR lfsr = new LFSR(initRegister, polynom);
        byte[] encrypted = lfsr.encrypt(message.getBytes());
        byte[] decrypted = lfsr.decrypt(encrypted);

        System.out.println("Original Message: " + message);
        System.out.println("Encrypted Message: " + new String(encrypted));
        System.out.println("Decrypted Message: " + new String(decrypted));

        lfsr.printPolynomialProperties();
    }
}
