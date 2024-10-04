
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

    private static String crackHybridPassword(String salt, String targetHash) throws NoSuchAlgorithmException {
        for (String password : dictionary) {
            String crackedPassword = tryAllTransformationsRealTime(password, salt, targetHash);
            if (crackedPassword != null) {
                return crackedPassword;
            }
        }
        return null;
    }

    private static String tryAllTransformationsRealTime(String password, String salt, String targetHash) throws NoSuchAlgorithmException {
        if (checkPassword(password, salt, targetHash)) {
            return password;
        }

        for (String passWithDigits : applyRandomDigitsRealTime(password)) {
            if (checkPassword(passWithDigits, salt, targetHash)) {
                return passWithDigits;
            }

            for (String caseTransformed : randomizeCasesRealTime(passWithDigits)) {
                if (checkPassword(caseTransformed, salt, targetHash)) {
                    return caseTransformed;
                }

                for (String swapped : swapLettersRealTime(caseTransformed)) {
                    if (checkPassword(swapped, salt, targetHash)) {
                        return swapped;
                    }
                }
            }
        }

        for (String swapped : swapLettersRealTime(password)) {
            if (checkPassword(swapped, salt, targetHash)) {
                return swapped;
            }

            for (String caseTransformed : randomizeCasesRealTime(swapped)) {
                if (checkPassword(caseTransformed, salt, targetHash)) {
                    return caseTransformed;
                }
            }
        }

        return null;
    }

    private static Iterable<String> applyRandomDigitsRealTime(String password) {
        List<String> variations = new ArrayList<>();
        for (int i = 0; i <= 9999; i++) {
            variations.add(password + String.format("%04d", i));
        }
        return variations;
    }

    private static Iterable<String> randomizeCasesRealTime(String password) {
        List<String> results = new ArrayList<>();
        int length = password.length();
        int combinations = 1 << length;

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

    private static Iterable<String> swapLettersRealTime(String password) {
        List<String> results = new ArrayList<>();
        results.add(password);

        for (int i = 0; i < password.length(); i++) {
            int currentSize = results.size();

            for (int j = 0; j < currentSize; j++) {
                char[] chars = results.get(j).toCharArray();
                switch (chars[i]) {
                    case 'e':
                        chars[i] = '3';
                        results.add(new String(chars));
                        chars[i] = 'e';
                        break;
                    case 'o':
                        chars[i] = '0';
                        results.add(new String(chars));
                        chars[i] = 'o';
                        break;
                    case 't':
                        chars[i] = '7';
                        results.add(new String(chars));
                        chars[i] = 't';
                        break;
                }
            }
        }
        return results;
    }

    private static boolean checkPassword(String password, String salt, String targetHash) throws NoSuchAlgorithmException {
        String saltedPassword = password + salt;
        String hash = md5Hash(saltedPassword);
        return hash.equals(targetHash);
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

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.out.println("Please provide an input file directory.");
            return;
        }

        String inputFile = args[0];
        String dictionaryFile = "./dictionary.csv";
        String outputFile = "task5.csv";

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

        System.out.println("File read successfully. Found " + users.size() + " users and " + dictionary.size() + " dictionary passwords");

        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int threadCount = Math.max(2, availableProcessors / 2);
        System.out.println("Using " + threadCount + " threads for execution.");

        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        List<Future<String[]>> results = new ArrayList<>();

        long startTime = System.currentTimeMillis();

        for (String[] user : users) {
            String username = user[0];
            String hash = user[1];
            String salt = user.length > 2 ? user[2] : "";

            Future<String[]> future = executorService.submit(() -> {
                String crackedPassword = crackHybridPassword(salt, hash);
                return new String[]{username, crackedPassword != null ? crackedPassword : "FAILED"};
            });

            results.add(future);
        }

        try (PrintWriter writer = new PrintWriter(new File(outputFile))) {
            int successCount = 0;
            for (Future<String[]> result : results) {
                String[] userResult = result.get();
                String username = userResult[0];
                String crackedPassword = userResult[1];

                writer.println(username + "," + crackedPassword);

                if (!crackedPassword.equals("FAILED")) {
                    System.out.println(username + ": " + crackedPassword);
                    successCount++;
                } else {
                    System.out.println(username + ": FAILED");
                }
            }

            long totalTime = (System.currentTimeMillis() - startTime) / 1000;
            double successRate = (double) successCount / users.size() * 100;

            writer.println("TOTALTIME," + totalTime);
            writer.println("SUCCESSRATE," + String.format("%.2f%%", successRate));

            System.out.println("Finished cracking. Total time: " + totalTime + " seconds. Success rate: " + successRate + "%");
        }

        executorService.shutdown();
    }
}
