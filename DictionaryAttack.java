
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class DictionaryAttack {

    private static List<String[]> users = new ArrayList<>();
    private static List<String> dictionary = new ArrayList<>();

    private static void readInputFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(",");
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

    private static String dictionaryAttack(String targetHash) throws NoSuchAlgorithmException {
        for (String password : dictionary) {
            String passwordHash = md5Hash(password);
            if (passwordHash.equals(targetHash)) {
                return password;
            }
        }
        return null;
    }

    private static String md5Hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] digest = md.digest(password.getBytes(StandardCharsets.UTF_8));

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
      
        String dictionaryFile = "./dictionary.csv";
        String inputFile = args[0];
        String outputFile = "task2.csv";

        System.out.println("Reading hashed password file: " + inputFile);
        readInputFile(inputFile);

        System.out.println("Reading dictionary file: " + dictionaryFile);
        readDictionaryFile(dictionaryFile);

        if (users.isEmpty()) {
            System.out.println("No users found in the file. Exiting.");
            return;
        }

        if (dictionary.isEmpty()) {
            System.out.println("No passwords found in the file. Exiting.");
        }

        System.out.println("File read successfully. Found " + users.size() + " users and " + dictionary.size() + " dictionary passwords");

        try (PrintWriter writer = new PrintWriter(new File(outputFile))) {
            long startTime = System.currentTimeMillis();
            int successCount = 0;

            for (String[] user : users) {
                String username = user[0];
                String hash = user[1];

                String crackedPassword = dictionaryAttack(hash);

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

    }

}
