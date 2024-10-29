package BSI.seguranca;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        System.out.print("1 - Novo usuário\n2 - Usuário Cadastrado\nInsira opção: ");
        Scanner sc = new Scanner(System.in);

        if(sc.next().equals("1")) {
            System.out.print("Insira usuário: ");
            String user = new Scanner(System.in).next();
            System.out.print("Insira senha semente: ");
            String seedPassword = new Scanner(System.in).next();
            System.out.print("Insira sal: ");
            String salt = new Scanner(System.in).next();
            System.out.print("Insira senha local: ");
            String localPassword = new Scanner(System.in).next();

            saveToFile(user, seedPassword, salt, localPassword);
        } else {
            System.out.print("Insira usuário: ");
            String user = new Scanner(System.in).next();
            System.out.print("Insira senha local: ");
            String password = new Scanner(System.in).next();

            if (checkPassword(user, password)) {
                System.out.println("Entrou");

                Socket clientSocket = new Socket("localhost", 12345);
                generateFile();
                PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
                BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

                String hashIndex = in.readLine();
                out.println(searchPassword(Integer.parseInt(hashIndex)));
            } else {
                System.out.println("Usuário ou senha não encontrados");
            }
        }
    }

    public static String searchPassword(int hashIndex) throws FileNotFoundException {
        int i = 0;
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/hashes.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        String password = "";

        while(i < hashIndex) {
            password = sc.next();
            i++;
        }

        return password;
    }

    public static String[] loadSalt() throws FileNotFoundException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/passwords.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);

        String[] password = sc.nextLine().split(" ");
        String[] pass = new String[2];
        pass[0] = password[2];
        pass[1] = password[3];

        return pass;
    }

    public static void generateFile() throws NoSuchAlgorithmException, IOException {
        String[] passwords = loadSalt();
        String timeSalt = LocalDateTime.now().toString().replaceAll("[-:.T]", "").substring(0, 12);
        String password = passwords[1].concat(passwords[0]).concat(timeSalt);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 5; i++) {
            password = hash(password);
            sb.append(password).append("\n");
        }

        saveToFileHash(sb.toString());
    }

    public static boolean checkPassword(String user, String password) throws FileNotFoundException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/passwords.txt";
        File file = new File(currentPath);

        Scanner myReader = new Scanner(file);
        SecretKey key = loadKey();
        while (myReader.hasNextLine()) {
            String[] data = myReader.nextLine().split(" ");
            String fileUser = data[0];
            String filePassword = data[1];

            if(fileUser.equals(user) && decrypt(filePassword, key).equals(password)) {
                return true;
            }
        }

        return false;
    }

    public static String hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : messageDigest) {
            hexString.append(String.format("%02X", 0xFF & b));
        }
        return hexString.substring(0,8);
    }

    public static SecretKey loadKey() throws FileNotFoundException {
        File file = new File(Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/keys.txt");
        Scanner sc = new Scanner(file);

        byte[] decodedKey = Base64.getDecoder().decode(sc.next());

        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        return keyGenerator.generateKey();
    }

    public static String encrypt(String input, SecretKey key) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }

    public static void saveToFile(String user, String seedPassword, String salt, String localPassword) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/passwords.txt";
        File file = new File(currentPath);
        if(!file.getParentFile().isFile()) file.getParentFile().mkdirs();
        SecretKey key = generateKey();
        byte[] rawData = key.getEncoded();
        String encodedKey = Base64.getEncoder().encodeToString(rawData);
        String encryptedPassword = encrypt(localPassword, key);
        String userData = user.concat(" " + encryptedPassword + " " + salt + " " + seedPassword);

        try (PrintWriter out = new PrintWriter(currentPath)) {
            out.println(userData);
        } catch (Exception e) {
            System.out.println("Arquivo não encontrado!");
        }

        try (PrintWriter out = new PrintWriter(Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/keys.txt")) {
            out.println(encodedKey);
        } catch (Exception e) {
            System.out.println("Arquivo não encontrado!");
        }
    }

    public static void saveToFileHash(String data) throws IOException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/hashes.txt";
        File file = new File(currentPath);
        file.getParentFile().mkdirs();

        try (PrintWriter out = new PrintWriter(currentPath)) {
            out.println(data);
        } catch (FileNotFoundException e) {
            System.out.println("Arquivo não encontrado!");
        }
    }
}