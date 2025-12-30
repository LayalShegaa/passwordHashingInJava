import org.mindrot.jbcrypt.BCrypt;

public class PasswordHasher {

    // Hash a password
    public static String hashPassword(String plainPassword) {
        return BCrypt.hashpw(plainPassword, BCrypt.gensalt());
    }

    // Verify a password
    public static boolean verifyPassword(String plainPassword,
                                         String hashedPassword) {
        return BCrypt.checkpw(plainPassword, hashedPassword);
    }

    public static void main(String[] args) {
        String password = "mySecurePassword123!";

        // Hash the password
        String hashed = hashPassword(password);
        System.out.println("Hashed: " + hashed);

        // Verify correct password
        boolean isValid = verifyPassword(password, hashed);
        System.out.println("Password valid: " + isValid);

        // Verify wrong password
        boolean isInvalid = verifyPassword("wrongPassword", hashed);
        System.out.println("Wrong password valid: " + isInvalid);
    }
}