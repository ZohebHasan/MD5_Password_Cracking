
import java.io.*;
import java.util.*;

public class PasswordTransformer {

    public static void main(String[] args) {
        String inputFile = "dictionary.csv"; 
        String outputFile = "dictionaryModified.csv"; 

        // Read the dictionary CSV file and apply transformations
        try (BufferedReader br = new BufferedReader(new FileReader(inputFile)); PrintWriter pw = new PrintWriter(new FileWriter(outputFile))) {
                        
            String line;
            while ((line = br.readLine()) != null) {
                String password = line.trim();
                List<String> transformedPasswords = applyTransformations(password);

                // Write each transformed password to the output file
                for (String transformed : transformedPasswords) {
                    pw.println(transformed);
                }
            }

            System.out.println("Password transformations completed. Transformed passwords saved to " + outputFile);
        } 
        catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Function to apply transformations to each password
    private static List<String> applyTransformations(String password) {
        List<String> transformedPasswords = new ArrayList<>();

        // Rule 1: Add up to 4 digits to the end of the password (limiting the number of variations)
        for (int i = 1; i <= 4; i++) {
            transformedPasswords.add(password + i);
        }

        // Rule 2: Replace certain characters (e -> 3, o -> 0, t -> 7)
        String replacedPassword = password.replace('e', '3')
                .replace('o', '0')
                .replace('t', '7');
        transformedPasswords.add(replacedPassword);

        // Rule 3: Change the case of certain letters
        // Capitalize the first letter
        String capitalized = capitalizeFirstLetter(password);
        transformedPasswords.add(capitalized);

        // Randomize case of letters (optional but providing one example)
        String randomizedCase = randomizeCase(password);
        transformedPasswords.add(randomizedCase);

        return transformedPasswords;
    }

    // Helper function to capitalize the first letter of the password
    private static String capitalizeFirstLetter(String password) {
        if (password == null || password.isEmpty()) {
            return password;
        }
        return Character.toUpperCase(password.charAt(0)) + password.substring(1);
    }

    // Helper function to randomize the case of letters in the password
    private static String randomizeCase(String password) {
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (char c : password.toCharArray()) {
            if (random.nextBoolean()) {
                sb.append(Character.toUpperCase(c));
            } else {
                sb.append(Character.toLowerCase(c));
            }
        }
        return sb.toString();
    }
}
