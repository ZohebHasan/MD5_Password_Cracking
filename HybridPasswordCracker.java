import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class HybridPasswordCracker {

    // A list of common passwords (the dictionary)
    private static List<String> commonPasswords = Arrays.asList(
        "password", "123456", "qwerty", "abc123", "letmein"
        // Add more passwords as needed
    );

    // Rules for replacing characters
    private static Map<Character, Character> replacements = Map.of(
        'e', '3',
        'o', '0',
        't', '7'
    );

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner stdin = new Scanner(System.in);

        System.out.print("Please enter your file directory for hashed passwords: ");
        String inputFile = stdin.nextLine();

        System.out.print("Please enter your file directory for the common password list: ");
        String dictionaryFile = stdin.nextLine();

        String targetHash = "e10adc3949ba59abbe56e057f20f883e"; 
        String salt = "abcd";  // Example salt
        
        for (String password : commonPasswords) {
            if (tryCrackPassword(password, targetHash, salt)) {
                System.out.println("Password cracked: " + password);
                break;
            }
        }
    }

    // Method to try cracking the password by generating variations
    private static boolean tryCrackPassword(String password, String targetHash, String salt) throws NoSuchAlgorithmException {
        // Generate variations: original password, with digits, and case changes
        List<String> variations = generateVariations(password);
        
        // Try each variation
        for (String variation : variations) {
            // Hash the variation with the salt
            String hash = md5Hash(variation + salt);
            
            // Compare the hash
            if (hash.equals(targetHash)) {
                System.out.println("Match found: " + variation);
                return true;
            }
        }
        
        return false;
    }

    // Method to generate variations of a password
    private static List<String> generateVariations(String basePassword) {
        List<String> variations = new ArrayList<>();
        
        // Original password
        variations.add(basePassword);
        
        // Rule 1: Adding digits to the end (up to 4 digits)
        for (int i = 1; i <= 9999; i++) {
            variations.add(basePassword + i);
        }

        // Rule 2: Replacing characters ('e' -> '3', 'o' -> '0', 't' -> '7')
        variations.add(replaceCharacters(basePassword));
        
        // Rule 3: Changing case (e.g., "password" -> "Password" or "PaSsWoRd")
        variations.add(basePassword.toUpperCase());
        variations.add(changeCaseRandomly(basePassword));
        
        return variations;
    }

    // Helper to replace characters based on the predefined replacement map
    private static String replaceCharacters(String password) {
        StringBuilder modified = new StringBuilder();
        for (char c : password.toCharArray()) {
            if (replacements.containsKey(c)) {
                modified.append(replacements.get(c));
            } else {
                modified.append(c);
            }
        }
        return modified.toString();
    }

    // Helper to randomly change the case of letters in the password
    private static String changeCaseRandomly(String password) {
        StringBuilder result = new StringBuilder();
        Random random = new Random();
        for (char c : password.toCharArray()) {
            if (Character.isLetter(c)) {
                // Randomly choose to uppercase or lowercase each letter
                if (random.nextBoolean()) {
                    result.append(Character.toUpperCase(c));
                } else {
                    result.append(Character.toLowerCase(c));
                }
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    // Method to calculate the MD5 hash of a given input
    private static String md5Hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
