package BSI.seguranca;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Server {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InterruptedException {
        System.out.println("1 - adicionar usuário\n2 - pedir hash");
        System.out.print("Entre a opção: ");
        Scanner scOption = new Scanner(System.in);
        String option = scOption.next();

        while(true) {

            if(option.equals("1")) {
                System.out.print("Entre o nome: ");
                Scanner scUser = new Scanner(System.in);
                String user = scUser.next();

                System.out.print("Entre senha semente: ");
                Scanner scPassword = new Scanner(System.in);
                String password = scPassword.next();

                System.out.print("Entre sal: ");
                Scanner scSalt = new Scanner(System.in);
                String salt = scSalt.next();

                saveData(user, hash(password), hash(salt));

                System.out.println("1 - adicionar usuário\n2 - pedir hash");
            } else {
                System.out.print("Entre qual usuário deseja: ");
                Scanner scUser = new Scanner(System.in);
                String clientUser = scUser.next();

                passwordHandler ph = new passwordHandler(clientUser);
                Thread thread = new Thread(ph);
                thread.start();
                System.out.print("Entre qual hash deseja: ");
                Scanner scIndex = new Scanner(System.in);
                String hashIndex = scIndex.next();

                if(searchPassword(hashIndex)) {
                    System.out.println("chave válida");
                    deleteHash(hashIndex);
                } else {
                    System.out.println("chave inválida");
                }
            }

            System.out.print("Entre a opção: ");
            scOption = new Scanner(System.in);
            option = scOption.next();
        }
    }

    public static String hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : messageDigest) {
            hexString.append(String.format("%02X", 0xFF & b));
        }

        return hexString.substring(0, 8);
    }

    public static void saveData(String user, String seedHash, String saltHash) {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/server/database.txt";
        File file = new File(currentPath);
        file.getParentFile().mkdirs();
        StringBuilder sb = new StringBuilder();
        sb.append(user).append("\n").append(seedHash).append("\n").append(saltHash).append("\n");

        try (PrintWriter out = new PrintWriter(new FileOutputStream(currentPath, true))) {
            out.println(sb);
        } catch (FileNotFoundException e) {
            System.out.println("Arquivo não encontrado!");
        }
    }

    public static void deleteHash(String hashValue) throws IOException {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/server/hashes.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        StringBuilder sb = new StringBuilder();

        while(sc.hasNext()) {
            String line = sc.nextLine();

            if(line.equals(hashValue)) break;

            sb.append(line).append('\n');
        }

        saveDataToFile(sb.toString());
    }

    public static boolean searchPassword(String hash) throws FileNotFoundException {
        String currentPath = Paths.get("").toAbsolutePath() + "\\src\\main\\java\\BSI\\seguranca\\server\\hashes.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);

        while(sc.hasNext()) {
            if(sc.nextLine().equals(hash)) {
                return true;
            }
        }

        return false;
    }

    public static void saveDataToFile(String data) {
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/server/hashes.txt";
        File file = new File(currentPath);
        file.getParentFile().mkdirs();

        try (PrintWriter out = new PrintWriter(currentPath)) {
            out.println(data);
        } catch (FileNotFoundException e) {
            System.out.println("Arquivo não encontrado!");
        }
    }
}
