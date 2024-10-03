
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class BruteForceCracker {

    private static final char[] CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
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

    private static String bruteForceCrack(String hash) throws NoSuchAlgorithmException {
        for (int length = 1; length <= 4; length++) {
            char[] currentPassword = new char[length];
            if (crackRecursive(hash, currentPassword, 0)) {
                return new String(currentPassword);
            }
        }
        return null;
    }

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
        Scanner stdin = new Scanner(System.in);

        System.out.print("Please enter your file directory: ");
        String inputFile = stdin.nextLine();
        String outputFile = "task1.csv";

        System.out.println("Reading input file: " + inputFile);
        readInputFile(inputFile);
        stdin.close();

        if (users.isEmpty()) {
            System.out.println("No users found in the file. Exiting.");
            return;
        } else {
            System.out.println("File read successfully. Found " + users.size() + " users.");
        }

      
        int availableProcessors = Runtime.getRuntime().availableProcessors();
        int threadCount = Math.max(2, availableProcessors / 2);  
        System.out.println("Using " + threadCount + " threads for execution.");

        ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
        List<Future<String[]>> results = new ArrayList<>();

        long startTime = System.currentTimeMillis();

  
        for (String[] user : users) {
            String username = user[0];
            String hash = user[1];

            Future<String[]> future = executorService.submit(() -> {
                String crackedPassword = bruteForceCrack(hash);
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

                System.out.println("Processing user: " + username + " - " + crackedPassword);
                writer.println(username + "," + crackedPassword);

                if (!crackedPassword.equals("FAILED")) {
                    successCount++;
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
