
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class SaltedPasswordCracker {

    private static List<String[]> users = new ArrayList<>();
    private static List<String> dictionary = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Scanner stdin = new Scanner(System.in);

        System.out.print("Please enter your file directory for salted passwords: ");
        String inputFile = stdin.nextLine();

        System.out.print("Please enter your file directory for the common password list: ");
        String dictionaryFile = stdin.nextLine();

        System.out.println("Reading salted password file: " + inputFile);
        readInputFile(inputFile);

        System.out.println("Reading dictionary file: " + dictionaryFile);
        readDictionaryFile(dictionaryFile);

        if (users.isEmpty()) {
            System.out.println("No users found in the file. Exiting.");
            return;
        }

        if (dictionary.isEmpty()) {
            System.out.println("No passwords have been found in the dictionary. Exiting");
            return;
        }

        System.out.println("File read successfully. Found " + users.size() + " users and " + dictionary.size() + " common passwords");

        try (PrintWriter writer = new PrintWriter(new File("task4.csv"))) {
            long startTime = System.currentTimeMillis();
            int successCount = 0;

            for (String[] user : users) {
                String username = user[0];
                String hashedPass = user[1];  
                String salt = user[2]; 
                // System.out.println("Processing user: " + username + " and the hashed pass is: " + hashedPass + " with salt: " + salt);

                String crackedPassword = crackSaltedPassword(salt, hashedPass);

                if (crackedPassword != null) {
                    System.out.println(username + ": " + crackedPassword);
                    writer.println(username + "," + crackedPassword);
                    successCount++;
                } else {
                    System.out.println(username + ": FAILED");
                    writer.println(username + ",FAILED");
                }
            }

            long totalTime = (System.currentTimeMillis() - startTime) / 1000;
            double successRate = (double) successCount / users.size() * 100;

            writer.println("TOTALTIME," + totalTime);
            writer.println("SUCCESSRATE," + String.format("%.2f%%", successRate));

            System.out.println("Finished cracking. Total time: " + totalTime + " seconds. Success rate: " + successRate + "%");
        }

        stdin.close();
    }

    private static void readInputFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(",");
            for (int i = 0; i < parts.length; i++) {
                parts[i] = parts[i].trim();  
            }
            users.add(parts);
        }
        reader.close();
    }

    private static void readDictionaryFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            dictionary.add(line.trim());
        }
        reader.close();
    }

    private static String crackSaltedPassword(String salt, String targetHash) throws NoSuchAlgorithmException {
        for (String password : dictionary) {
            String saltedPassword = password + salt;
            String hash = md5Hash(saltedPassword); 
            if (hash.equals(targetHash)) {
                return password;  
            }
        }
        return null; 
    }

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
