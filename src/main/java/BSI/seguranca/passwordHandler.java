package BSI.seguranca;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Scanner;

public class passwordHandler implements Runnable {
    public String user;

    public passwordHandler(String user) {
        this.user = user;
    }

    @Override
    public void run() {
        try {
            minuteCheck();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String[] getHashes() throws FileNotFoundException, NoSuchAlgorithmException {
        String currentPath = Paths.get("").toAbsolutePath() + "\\src\\main\\java\\BSI\\seguranca\\server\\database.txt";
        File file = new File(currentPath);
        Scanner sc = new Scanner(file);
        int i = 0;
        boolean userFound = false;
        String data = "";

        while (sc.hasNext() && !userFound) {
            if(i % 5 == 0) {
                data = sc.nextLine();
                if(data.equals(user)) {
                    userFound = true;
                }
            }
            i++;
        }

        String[] dataHash = new String[2];
        dataHash[0] = sc.nextLine();
        dataHash[1] = sc.nextLine();

        return dataHash;
    }

    public String hash(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageDigest = md.digest(password.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();
        for (byte b : messageDigest) {
            hexString.append(String.format("%02X", 0xFF & b));
        }

        return hexString.substring(0, 8);
    }

    public void minuteCheck() throws NoSuchAlgorithmException, IOException {
        LocalDateTime timeNow = LocalDateTime.now();
        LocalDateTime addMinute = timeNow.plusMinutes(1);
        generatePassword();

        while(true) {
            timeNow = LocalDateTime.now();

            if(timeNow.getMinute() == addMinute.getMinute() && timeNow.getSecond() == addMinute.getSecond()) {
                addMinute = timeNow.plusMinutes(1);
                generatePassword();
            }
        }
    }

    public void generatePassword() throws NoSuchAlgorithmException, IOException {
        String[] hashes = getHashes();
        String timeSalt = LocalDateTime.now().toString().replaceAll("[-:.T]", "").substring(0, 12);
        String hashTime = hash(timeSalt);
        String password = hashes[0].concat(hashes[1]).concat(hashTime);
        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < 5; i++) {
            password = hash(password);
            sb.append(password).append("\n");
        }

        saveToFile(sb.toString());
    }

    public static void saveToFile(String data) {
        String currentPath = Paths.get("").toAbsolutePath() + "\\src\\main\\java\\BSI\\seguranca\\server\\hashes.txt";
        File file = new File(currentPath);
        if(!file.getParentFile().isFile()) file.getParentFile().mkdirs();

        try (PrintWriter out = new PrintWriter(new FileOutputStream(currentPath, false))) {
            out.println(data);
        } catch (FileNotFoundException e) {
            System.out.println("Arquivo não encontrado!");
        }
    }
}
