package BSI.seguranca;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;

public class passwordHandler implements Runnable {
    String salt;
    String seedPassword;

    public passwordHandler (String seedPassword, String salt) {
        this.salt = salt;
        this.seedPassword = seedPassword;
    }

    @Override
    public void run() {
        try {
            minuteCheck();
        } catch (NoSuchAlgorithmException | IOException e) {
            throw new RuntimeException(e);
        }
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
        String timeSalt = LocalDateTime.now().toString().replaceAll("[-:.T]", "").substring(0, 12);
        String password = seedPassword.concat(salt).concat(timeSalt);
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
