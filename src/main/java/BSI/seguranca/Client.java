package BSI.seguranca;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    static String salt;
    static String seedPassword;
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        while(true) {
            System.out.print("1 - Novo usuário\n2 - Usuário Cadastrado\nInsira opção: ");
            Scanner sc = new Scanner(System.in);

            if (sc.next().equals("1")) {
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

                    out.println(user);
                    String hashIndex = in.readLine();
                    String hashPassword = searchPassword(Integer.parseInt(hashIndex));
                    out.println(hashPassword);
                    System.out.printf("O hash é %s e está no index %s\n", hashPassword, hashIndex);
                    String resp = in.readLine();

                    if (resp.equals("válido")) {
                        deleteHash(Integer.parseInt(hashIndex));
                        System.out.println("Hash utilizada e as seguintes foram deletada do arquivo.");
                    }
                } else {
                    System.out.println("Usuário ou senha não encontrados");
                }
            }
        }
    }

    public static boolean checkPassword(String user, String password) throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/passwords.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);

        while (sc.hasNext()) {
            String bytes = sc.nextLine();
            salt = bytes.substring(0, bytes.length() - 24);

            String userData = decrypt(bytes.replaceAll(salt, ""), stringToSecretKey(password, salt));
            String[] userDataArray = userData.split(" ");
            if(!userData.isEmpty() && userDataArray[0].equals(user)) {
                seedPassword = userDataArray[1];
                return true;
            }
        }

        return false;
    }

    public static void deleteHash(int hashIndex) throws IOException {
        int i = 0;
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/hashes.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        StringBuilder sb = new StringBuilder();

        while(sc.hasNext()) {
            if(i == hashIndex) break;

            sb.append(sc.next()).append("\n");
            i++;
        }

        saveDataToFile(sb.toString());
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

    public static void generateFile() throws NoSuchAlgorithmException, IOException {
        String timeSalt = LocalDateTime.now().toString().replaceAll("[-:.T]", "").substring(0, 12);
        timeSalt = hash(timeSalt);
        String hashSalt = hash(salt);
        String hashPassword = hash(seedPassword);
        String finalHash = hashPassword.concat(hashSalt).concat(timeSalt);
        System.out.println(finalHash);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 5; i++) {
            finalHash = hash(finalHash);
            sb.append(finalHash).append("\n");
        }

        saveDataToFile(sb.toString());
    }

    public static SecretKey stringToSecretKey(String password, String salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(spec).getEncoded();

        return new SecretKeySpec(keyBytes, "AES");
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

    public static String encrypt(String input, String key, String salt) throws
            NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, stringToSecretKey(key, salt));
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key) throws
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
            return new String(plainText);
        } catch(BadPaddingException e) {
            return "";
        }
    }

    public static void saveToFile(String user, String seedPassword, String salt, String localPassword) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidKeySpecException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/client/passwords.txt";
        File file = new File(currentPath);
        if(!file.getParentFile().isFile()) file.getParentFile().mkdirs();
        String userData = user.concat(" " + seedPassword);
        userData = encrypt(userData, localPassword, salt);
        try (PrintWriter out = new PrintWriter(new FileOutputStream(currentPath, true))) {
            out.println(salt + userData);
        } catch (Exception e) {
            System.out.println("Arquivo não encontrado!");
        }
    }

    public static void saveDataToFile(String data) {
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