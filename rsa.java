import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Scanner;

class RSA {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Input: Plain text
        System.out.print("Enter the plain text: ");
        String plainText = scanner.nextLine();

        System.out.println("\nEncryption and Decryption Process:\n");

        // Process each character in the plain text
        for (char ch : plainText.toCharArray()) {
            // Convert character to ASCII
            int asciiValue = (int) ch;

            // Generate RSA keys for the character
            RSAKeyPair keyPair = generateRSAKeys(asciiValue);

            // Encrypt the ASCII value
            BigInteger encryptedValue = squareAndMultiply(BigInteger.valueOf(asciiValue), keyPair.getPublicKey(), keyPair.getN());

            // Decrypt the value using CRT
            BigInteger decryptedValue = decryptWithCRT(encryptedValue, keyPair);

            // Output results
            System.out.println("Character: '" + ch + "'");
            System.out.println("ASCII Value: " + asciiValue);
            System.out.println("p: " + keyPair.getP());
            System.out.println("q: " + keyPair.getQ());
            System.out.println("Public Key (e): " + keyPair.getPublicKey());
            System.out.println("Private Key (d): " + keyPair.getPrivateKey());
            System.out.println("Encrypted ASCII (Cipher Text): " + encryptedValue);
            System.out.println("Decrypted ASCII: " + decryptedValue);
            System.out.println("------------------------------------\n");
        }

        scanner.close();
    }

    // Generate RSA keys
    private static RSAKeyPair generateRSAKeys(int asciiValue) {
        SecureRandom random = new SecureRandom();
        BigInteger p, q;
        int maxAttempts = 100; // Limit attempts to prevent infinite loop
        int attempts = 0;

        // Define the range for primes
        BigInteger lowerBound = BigInteger.valueOf(asciiValue).add(BigInteger.ONE);
        BigInteger upperBound = BigInteger.valueOf(2).pow(15).subtract(BigInteger.ONE);

        // Generate p using constraints and Fermat Primality Test
        do {
            if (attempts++ > maxAttempts) {
                throw new RuntimeException("Failed to generate prime p within constraints.");
            }
            p = generateRandomPrimeInRange(lowerBound, upperBound, random);
            System.out.println("Trying p: " + p); // Debugging statement
        } while (!isPrimeFermat(p, 10));

        attempts = 0; // Reset attempts for q

        // Generate q using constraints and Fermat Primality Test
        do {
            if (attempts++ > maxAttempts) {
                throw new RuntimeException("Failed to generate prime q within constraints.");
            }
            q = generateRandomPrimeInRange(lowerBound, upperBound, random);
            System.out.println("Trying q: " + q); // Debugging statement
        } while (!isPrimeFermat(q, 10) || p.equals(q));

        // Calculate n = p * q
        BigInteger n = p.multiply(q);

        // Calculate phi(n) = (p - 1) * (q - 1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // Choose e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
        BigInteger e;
        do {
            e = new BigInteger(phi.bitLength(), random);
        } while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));

        // Calculate d using Extended Euclidean Algorithm
        BigInteger d = extendedEuclidean(e, phi)[1].mod(phi);

        return new RSAKeyPair(p, q, n, e, d);
    }

    // Generate a random prime within a specific range
    private static BigInteger generateRandomPrimeInRange(BigInteger lowerBound, BigInteger upperBound, SecureRandom random) {
        BigInteger range = upperBound.subtract(lowerBound);
        BigInteger candidate;
        do {
            candidate = new BigInteger(range.bitLength(), random).add(lowerBound);
        } while (candidate.compareTo(upperBound) >= 0 || candidate.compareTo(lowerBound) <= 0);
        return candidate;
    }


    // Fermat Primality Test
    private static boolean isPrimeFermat(BigInteger n, int iterations) {
        if (n.compareTo(BigInteger.ONE) <= 0) return false;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < iterations; i++) {
            BigInteger a = BigInteger.valueOf(2).add(new BigInteger(n.bitLength() - 1, random));
            if (!squareAndMultiply(a, n.subtract(BigInteger.ONE), n).equals(BigInteger.ONE)) {
                return false;
            }
        }
        return true;
    }

    // Square and Multiply Algorithm for Exponentiation
    private static BigInteger squareAndMultiply(BigInteger base, BigInteger exponent, BigInteger modulus) {
        BigInteger result = BigInteger.ONE;
        String binary = exponent.toString(2);
        for (char bit : binary.toCharArray()) {
            result = result.multiply(result).mod(modulus);
            if (bit == '1') {
                result = result.multiply(base).mod(modulus);
            }
        }
        return result;
    }

    // Extended Euclidean Algorithm
    private static BigInteger[] extendedEuclidean(BigInteger a, BigInteger b) {
        if (b.equals(BigInteger.ZERO)) {
            return new BigInteger[]{a, BigInteger.ONE, BigInteger.ZERO};
        }
        BigInteger[] values = extendedEuclidean(b, a.mod(b));
        BigInteger gcd = values[0];
        BigInteger x = values[2];
        BigInteger y = values[1].subtract(a.divide(b).multiply(values[2]));
        return new BigInteger[]{gcd, x, y};
    }

    // Decrypt using Chinese Remainder Theorem
    private static BigInteger decryptWithCRT(BigInteger cipherText, RSAKeyPair keyPair) {
        BigInteger p = keyPair.getP();
        BigInteger q = keyPair.getQ();
        BigInteger dp = keyPair.getPrivateKey().mod(p.subtract(BigInteger.ONE));
        BigInteger dq = keyPair.getPrivateKey().mod(q.subtract(BigInteger.ONE));
        BigInteger qInv = extendedEuclidean(q, p)[1].mod(p);

        BigInteger m1 = squareAndMultiply(cipherText, dp, p);
        BigInteger m2 = squareAndMultiply(cipherText, dq, q);
        BigInteger h = qInv.multiply(m1.subtract(m2)).mod(p);
        return m2.add(h.multiply(q));
    }
}

// Helper class to store RSA keys
class RSAKeyPair {
    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger n;
    private final BigInteger publicKey;
    private final BigInteger privateKey;

    public RSAKeyPair(BigInteger p, BigInteger q, BigInteger n, BigInteger publicKey, BigInteger privateKey) {
        this.p = p;
        this.q = q;
        this.n = n;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
}
