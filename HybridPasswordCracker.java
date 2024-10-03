import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class HybridPasswordCracker {

    private static List<String[]> users = new ArrayList<>();
    private static List<String> dictionary = new ArrayList<>();
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors();

    // Read user info (e.g., username, hashed password, salt)
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

    // Read dictionary of common passwords
    private static void readDictionaryFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            dictionary.add(line.trim());
        }
        reader.close();
    }

    // Hybrid password cracker (multithreaded)
    private static String crackHybridPassword(String salt, String targetHash) throws NoSuchAlgorithmException {
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);

        // Submit tasks for each dictionary word
        List<Future<String>> results = new ArrayList<>();
        for (String password : dictionary) {
            Future<String> result = executor.submit(() -> {
                // Try original and transformed passwords
                return tryAllTransformations(password, salt, targetHash);
            });
            results.add(result);
        }

        // Wait for results
        for (Future<String> result : results) {
            try {
                String crackedPassword = result.get();
                if (crackedPassword != null) {
                    executor.shutdown();
                    return crackedPassword;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        executor.shutdown();
        return null;
    }

    private static String tryAllTransformations(String password, String salt, String targetHash) throws NoSuchAlgorithmException {
        // Try the original password
        if (checkPassword(password, salt, targetHash)) {
            return password;
        }

        // Try all combinations of transformations
        List<String> variations = applyAllTransformations(password);
        for (String variation : variations) {
            if (checkPassword(variation, salt, targetHash)) {
                return variation;
            }
        }

        return null;
    }

    // Apply all transformations: add digits, randomize case, swap letters
    private static List<String> applyAllTransformations(String password) {
        List<String> transformedPasswords = new ArrayList<>();

        // Add all digit combinations
        transformedPasswords.addAll(applyRandomDigits(password));

        // For each variation with digits, apply case randomization and swaps
        List<String> tempPasswords = new ArrayList<>(transformedPasswords);
        for (String pass : tempPasswords) {
            transformedPasswords.addAll(randomizeCases(pass));
            transformedPasswords.addAll(swapLetters(pass));
        }

        return transformedPasswords;
    }

    // Generate all combinations of digits from 0-9999 appended to the password
    private static List<String> applyRandomDigits(String password) {
        List<String> variations = new ArrayList<>();
        for (int i = 0; i <= 9999; i++) {
            variations.add(password + String.format("%04d", i));  // Pad numbers to ensure 4 digits
        }
        return variations;
    }

    // Randomize the case for every possible letter combination
    private static List<String> randomizeCases(String password) {
        List<String> results = new ArrayList<>();
        int length = password.length();
        int combinations = 1 << length;  // 2^length combinations for case changes

        for (int i = 0; i < combinations; i++) {
            StringBuilder sb = new StringBuilder(password);
            for (int j = 0; j < length; j++) {
                if ((i & (1 << j)) != 0) {
                    sb.setCharAt(j, Character.toUpperCase(password.charAt(j)));
                } else {
                    sb.setCharAt(j, Character.toLowerCase(password.charAt(j)));
                }
            }
            results.add(sb.toString());
        }

        return results;
    }

    // Swap letters 'e', 'o', 't' with '3', '0', '7' and try all combinations
    private static List<String> swapLetters(String password) {
        List<String> results = new ArrayList<>();
        swapRecursive(password.toCharArray(), 0, results);
        return results;
    }

    // Recursive function to generate all combinations of letter swaps
    private static void swapRecursive(char[] password, int index, List<String> results) {
        if (index == password.length) {
            results.add(new String(password));
            return;
        }

        char currentChar = password[index];
        switch (currentChar) {
            case 'e':
                password[index] = '3';
                swapRecursive(password, index + 1, results);
                password[index] = 'e';  // Backtrack
                break;
            case 'o':
                password[index] = '0';
                swapRecursive(password, index + 1, results);
                password[index] = 'o';  // Backtrack
                break;
            case 't':
                password[index] = '7';
                swapRecursive(password, index + 1, results);
                password[index] = 't';  // Backtrack
                break;
            default:
                break;
        }
        // Try the current character as is
        swapRecursive(password, index + 1, results);
    }

    // Check if the password (or its variation) matches the hash
    private static boolean checkPassword(String password, String salt, String targetHash) throws NoSuchAlgorithmException {
        String saltedPassword = password + salt;
        String hash = md5Hash(saltedPassword);
        return hash.equals(targetHash);
    }

    // MD5 hash function
    private static String md5Hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));

        StringBuilder sb = new StringBuilder();
        for (byte b : digest) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Scanner stdin = new Scanner(System.in);

        System.out.print("Please enter your file directory for salted passwords: ");
        String inputFile = stdin.nextLine();

        System.out.print("Please enter your file directory for the dictionary: ");
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
            System.out.println("No passwords found in the dictionary. Exiting.");
            return;
        }

        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int threadCount = Math.max(2, availableProcessors / 2);  
        System.out.println("Using " + threadCount + " threads for execution.");


        System.out.println("File read successfully. Found " + users.size() + " users and " + dictionary.size() + " dictionary passwords");

        try (PrintWriter writer = new PrintWriter(new File("task5.csv"))) {
            long startTime = System.currentTimeMillis();
            int successCount = 0;

            for (String[] user : users) {
                String username = user[0];
                String hashedPass = user[1];
                String salt = user.length > 2 ? user[2] : "";

                String crackedPassword = crackHybridPassword(salt, hashedPass);

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
}