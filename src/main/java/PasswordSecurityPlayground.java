import org.mindrot.jbcrypt.BCrypt;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class PasswordSecurityPlayground {

    public static void main(String[] args) throws Exception {

        String password = "SecurePass123!";

        System.out.println("===== PASSWORD SECURITY PLAYGROUND =====\n");

        // Klartext (schlecht)
        System.out.println("1) Klartext:");
        System.out.println(password + "\n");

        //Encoding (Base64)
        System.out.println("2) Encoding (Base64 - NICHT sicher):");
        String encoded = Base64.getEncoder()
                .encodeToString(password.getBytes());
        System.out.println(encoded + "\n");

        //  SHA-256 (zu schnell)
        System.out.println("3) SHA-256 Hash (nicht ideal für Passwörter):");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] shaHash = sha256.digest(password.getBytes(StandardCharsets.UTF_8));
        System.out.println(bytesToHex(shaHash) + "\n");

        //  BCrypt (empfohlen)
        System.out.println("4) BCrypt Hash:");
        long startBCrypt = System.currentTimeMillis();
        String bcryptHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
        long endBCrypt = System.currentTimeMillis();

        System.out.println(bcryptHash);
        System.out.println("BCrypt Zeit: " + (endBCrypt - startBCrypt) + " ms");

        System.out.println("BCrypt korrekt? " +
                BCrypt.checkpw(password, bcryptHash));
        System.out.println();

        //  Argon2 (modern & sehr sicher)
        System.out.println("5) Argon2 Hash:");
        Argon2 argon2 = Argon2Factory.create();

        long startArgon2 = System.currentTimeMillis();
        String argonHash = argon2.hash(
                2,      // Iterationen
                65536,  // Memory (64 MB)
                1,      // Parallelism
                password.toCharArray()
        );
        long endArgon2 = System.currentTimeMillis();

        System.out.println(argonHash);
        System.out.println("Argon2 Zeit: " + (endArgon2 - startArgon2) + " ms");

        System.out.println("Argon2 korrekt? " +
                argon2.verify(argonHash, password.toCharArray()));
        System.out.println();


    }

    // Hilfsmethode für SHA-256
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
