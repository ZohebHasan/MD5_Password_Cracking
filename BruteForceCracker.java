import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class BruteForceCracker {

    private static final char[] CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
    private static List<String[]> users = new ArrayList<>();

    // Method to read the input file
    private static void readInputFile(String fileName) throws IOException {
        BufferedReader br = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = br.readLine()) != null) {
            String[] parts = line.split(",");
            users.add(parts);
        }
        br.close();
    }

    // Method to attempt brute force cracking
    private static String bruteForceCrack(String hash) throws NoSuchAlgorithmException {
        for (int length = 1; length <= 4; length++) {
            char[] currentPassword = new char[length];  // Define currentPassword here
            if (crackRecursive(hash, currentPassword, 0)) {
                return new String(currentPassword);  // Return the correct password
            }
        }
        return null;
    }

    // Recursive method to generate all combinations
    private static boolean crackRecursive(String targetHash, char[] currentPassword, int position) throws NoSuchAlgorithmException {
        if (position == currentPassword.length) {
            String guess = new String(currentPassword);
            String guessHash = md5Hash(guess);
            return guessHash.equals(targetHash);
        }

        for (char c : CHARSET) {
            currentPassword[position] = c;
            if (crackRecursive(targetHash, currentPassword, position + 1)) {
                return true;
            }
        }

        return false;
    }

    // Method to compute MD5 hash
    private static String md5Hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));

        // Convert byte array into hexadecimal format
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        String inputFile = "/Users/zohebhasan/Downloads/sample_100_pass.csv";
        String outputFile = "task1.csv";
    
        // Step 1: Read the input CSV
        System.out.println("Reading input file: " + inputFile);
        readInputFile(inputFile);
        
        // Check if users list is populated
        if (users.isEmpty()) {
            System.out.println("No users found in the file. Exiting.");
            return;
        } else {
            System.out.println("File read successfully. Found " + users.size() + " users.");
        }
    
        // Step 2: Brute-force cracking for each user
        try (PrintWriter writer = new PrintWriter(new File(outputFile))) {
            long startTime = System.currentTimeMillis();
            int successCount = 0;
    
            for (String[] user : users) {
                String username = user[0];
                String hash = user[1];
                System.out.println("Processing user: " + username + " with hash: " + hash);
    
                String crackedPassword = bruteForceCrack(hash);
    
                if (crackedPassword != null) {
                    System.out.println("Password for " + username + " cracked: " + crackedPassword);
                } else {
                    System.out.println("Failed to crack password for " + username);
                }
    
                writer.println(username + "," + (crackedPassword != null ? crackedPassword : "FAILED"));
                if (crackedPassword != null) {
                    successCount++;
                }
            }
    
            long totalTime = (System.currentTimeMillis() - startTime) / 1000;
            double successRate = (double) successCount / users.size() * 100;
    
            // Step 3: Write time and success rate
            writer.println("TOTALTIME," + totalTime);
            writer.println("SUCCESSRATE," + String.format("%.2f%%", successRate));
    
            System.out.println("Finished cracking. Total time: " + totalTime + " seconds. Success rate: " + successRate + "%");
        }
    }
    

}