package BSI.seguranca;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Paths;
import java.util.Random;
import java.util.Scanner;

public class Server {
    public static void main(String[] args) throws IOException {
        System.out.print("Entre senha semente: ");
        Scanner scPassword = new Scanner(System.in);
        String password = scPassword.next();

        System.out.print("Entre sal: ");
        Scanner scSalt = new Scanner(System.in);
        String salt = scSalt.next();

        passwordHandler ph = new passwordHandler(password, salt);
        Thread thread = new Thread(ph);
        thread.start();

        Random ran = new Random();
        int hashIndex = ran.nextInt(4) - 1;
        ServerSocket serverSocket = new ServerSocket(12345);
        Socket clientSocket = serverSocket.accept();
        System.out.println("cliente aceito" + clientSocket.getInetAddress().toString());
        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));

        out.println(hashIndex);
        String hashPassword = in.readLine();
        if(hashPassword.equals(searchPassword(hashIndex))) {
            System.out.println("Chave válida.");
        } else {
            System.out.println("Chave inválida.");
        }
    }

    public static String searchPassword(int hashIndex) throws FileNotFoundException {
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
}
