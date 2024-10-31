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
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        System.out.println("1 - adicionar usuário\n2 - pedir hash");
        System.out.print("Entre a opção: ");
        Scanner scOption = new Scanner(System.in);
        String option = scOption.next();

        while(option.equals("1")) {
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
            System.out.print("Entre a opção: ");
            scOption = new Scanner(System.in);
            option = scOption.next();
        }

        ServerSocket serverSocket = new ServerSocket(12345);
        Socket clientSocket = serverSocket.accept();
        System.out.println("cliente aceito" + clientSocket.getInetAddress().toString());
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String clientUser = in.readLine();

        passwordHandler ph = new passwordHandler(clientUser);
        Thread thread = new Thread(ph);
        thread.start();
        System.out.print("Entre qual hash deseja: ");
        Scanner scIndex = new Scanner(System.in);
        String hashIndex = scIndex.next();

        out.println(hashIndex);
        String hashPassword = in.readLine();
        if(hashPassword.equals(searchPassword(Integer.parseInt(hashIndex), clientUser))) {
            System.out.printf("O hash é %s e está no index %s\n", hashPassword, hashIndex);
            System.out.println("Chave válida.");
            out.println("válido");
            deleteHash(Integer.parseInt(hashIndex));
        } else {
            System.out.printf("O hash é %s e está no index %s\n", hashPassword, hashIndex);
            System.out.println("Chave inválida.");
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

    public static void deleteHash(int hashIndex) throws IOException {
        int i = 0;
        String currentPath = Paths.get("").toAbsolutePath() + "/src/main/java/BSI/seguranca/server/hashes.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        StringBuilder sb = new StringBuilder();

        while(sc.hasNext()) {
            if(i == hashIndex) break;

            sb.append(sc.next()).append('\n');
            i++;
        }

        saveDataToFile(sb.toString());
    }

    public static String searchPassword(int hashIndex, String user) throws FileNotFoundException {
        String currentPath = Paths.get("").toAbsolutePath() + "\\src\\main\\java\\BSI\\seguranca\\server\\hashes.txt";
        int i = 0;
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        String password = "";

        while(i < hashIndex) {
            password = sc.next();
            i++;
        }

        return password;
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
