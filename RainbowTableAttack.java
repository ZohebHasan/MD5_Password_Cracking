
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class RainbowTableAttack {

    private static Map<String, String> rainbowTable = new HashMap<>();
    private static List<String[]> users = new ArrayList<>();

    private static void readInputFile(String fileName) throws IOException {
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(",");
            users.add(parts);
        }
        reader.close();
    }

    private static void buildRainbowTable(String dictionaryFile) throws IOException, NoSuchAlgorithmException {
        BufferedReader reader = new BufferedReader(new FileReader(dictionaryFile));
        String password;
        while ((password = reader.readLine()) != null) {
            String hash = md5Hash(password.trim());
            rainbowTable.put(hash, password);
        }
        reader.close();
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
        String inputFile = args[0];
        String dictionaryFile = "./dictionary.csv";
        String outputFile = "task3.csv";

        System.out.println("Reading hashed password file: " + inputFile);
        readInputFile(inputFile);

        System.out.println("Building the rainbow table...");
        buildRainbowTable(dictionaryFile);

        if (users.isEmpty()) {
            System.out.println("No users found in the file. Exiting.");
            return;
        }

        System.out.println("File read successfully. Found " + users.size() + " users.");

        try (PrintWriter writer = new PrintWriter(new File(outputFile))) {
            long startTime = System.currentTimeMillis();
            int successCount = 0;

            for (String[] user : users) {
                String username = user[0];
                String hash = user[1];

                String crackedPassword = rainbowTable.get(hash);

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
