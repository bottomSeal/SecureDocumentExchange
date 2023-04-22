package com.example.securedocumentexchange.security;

import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.SshPublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class SecurityServiceImpl implements SecurityService{

    PublicKey publicKey;

    PrivateKey privateKey;

    private byte[] encrypt(String message, File publicKeyFile) throws IOException, GeneralSecurityException {
        SshPublicKey sshPublicKey = SshKeyUtils.getPublicKey(publicKeyFile);

        publicKey = sshPublicKey.getJCEPublicKey();

        Key aesKey = generateAes(128);

        IvParameterSpec iv = generateIv(aesKey.getEncoded().length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(128, iv.getIV()));

        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encryptedAesKey = cipher.doFinal(aesKey.getEncoded());

        byte[] outputMessageWithKey = new byte[encryptedBytes.length + encryptedAesKey.length + iv.getIV().length];

        System.arraycopy(iv.getIV(), 0, outputMessageWithKey,0, iv.getIV().length);

        System.arraycopy(encryptedAesKey, 0, outputMessageWithKey, iv.getIV().length, encryptedAesKey.length);

        System.arraycopy(encryptedBytes, 0, outputMessageWithKey, iv.getIV().length + encryptedAesKey.length, encryptedBytes.length);

        return outputMessageWithKey;
    }

    private String decrypt(byte[] encodedBytes, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        byte[] iv = Arrays.copyOfRange(encodedBytes, 0, 16);

        byte[] aesKeyEnc = Arrays.copyOfRange(encodedBytes, 16, 512+16);

        byte[] dataEnc = Arrays.copyOfRange(encodedBytes, 512+16, encodedBytes.length);

        privateKey = SshKeyUtils.getPrivateKey(privateKeyFile, "").getPrivateKey().getJCEPrivateKey();

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decodedAesKey = cipher.doFinal(aesKeyEnc);

        Key aesKey = new SecretKeySpec(decodedAesKey, "AES");

        cipher = Cipher.getInstance("AES/GCM/NoPadding");

        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(128, iv));

        byte[] decodedData = cipher.doFinal(dataEnc);

        String data = new String(decodedData, "UTF-8");

        return data;
    }

    @Override
    public String encryptMessage(String message, File publicKeyFile) throws IOException, GeneralSecurityException {

        byte[] outputMessageWithKey = encrypt(message, publicKeyFile);

        return Base64.getEncoder().encodeToString(outputMessageWithKey);
    }

    private SecretKeySpec generateAes(int keySize) {
        byte[] aesByte = new byte[keySize / 8];

        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(aesByte);

        return new SecretKeySpec(aesByte, "AES");
    }

    private IvParameterSpec generateIv(int keySize) {
        byte[] ivByte = new byte[keySize];

        SecureRandom secureRandom = new SecureRandom();

        secureRandom.nextBytes(ivByte);

        return new IvParameterSpec(ivByte);
    }

    @Override
    public String decryptMessage(String message, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        byte[] encodedBytes = Base64.getDecoder().decode(message);

        String data = decrypt(encodedBytes, privateKeyFile);

        return data;
    }

    private String readFromFile(File document) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        String line;

        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(document))) {
            while ((line = bufferedReader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
        }

        return stringBuilder.toString();
    }

    private void writeStringToFile(File file, String data) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(data);
        }
    }

    private byte[] readByteArrayFromFile(File document) throws IOException {
        byte[] byteArray;

        try (FileInputStream inputStream = new FileInputStream(document)) {
            int fileSize = (int) document.length();
            byteArray = new byte[fileSize];
            inputStream.read(byteArray);
        }

        return byteArray;
    }

    private void writeByteArrayToFile(File file, byte[] data) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(file)) {
            outputStream.write(data);
            outputStream.flush();
        }
    }

    @Override
    public void encryptDocument(File document, File openKey) throws IOException, GeneralSecurityException {
        String data = readFromFile(document);

        byte[] encryptedData = encrypt(data, openKey);

        File newFile = new File("C:\\Users\\petre\\OneDrive\\Рабочий стол\\encrypted_document", document.getName());

        writeByteArrayToFile(newFile, encryptedData);
    }

    @Override
    public void decryptDocument(File document, File secretKey) throws IOException, GeneralSecurityException, InvalidPassphraseException {
        byte[] data = readByteArrayFromFile(document);

        String decryptedData = decrypt(data, secretKey);

        File newFile = new File("C:\\Users\\petre\\OneDrive\\Рабочий стол\\decrypted_document", document.getName());

        writeStringToFile(newFile, decryptedData);
    }

    @Override
    public void signDocument(File document, File privateKey) throws IOException, GeneralSecurityException, InvalidPassphraseException {

    }

    @Override
    public boolean verifyDocument(File document, File signFile, File publicKey) throws IOException, GeneralSecurityException {
        return false;
    }
}
