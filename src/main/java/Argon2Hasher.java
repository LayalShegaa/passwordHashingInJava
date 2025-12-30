import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public class Argon2Hasher {

    private static final Argon2 argon2 = Argon2Factory.create();

    // Hash a password
    public static String hashPassword(String password) {
        try {
            // iterations=2, memory=65536 KB, parallelism=1
            return argon2.hash(2, 65536, 1, password.toCharArray());
        } finally {
            // Clear sensitive data from memory
            argon2.wipeArray(password.toCharArray());
        }
    }

    // Verify a password
    public static boolean verifyPassword(String password, String hash) {
        try {
            return argon2.verify(hash, password.toCharArray());
        } finally {
            argon2.wipeArray(password.toCharArray());
        }
    }

    public static void main(String[] args) {
        String password = "mySecurePassword123!";

        String hashed = hashPassword(password);
        System.out.println("Hashed: " + hashed);

        boolean isValid = verifyPassword(password, hashed);
        System.out.println("Password valid: " + isValid);
    }
}