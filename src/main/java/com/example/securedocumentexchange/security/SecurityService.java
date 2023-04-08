package com.example.securedocumentexchange.security;

import com.sshtools.common.publickey.InvalidPassphraseException;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;

public interface SecurityService {

    String encryptMessage(String message, File publicKeyFile) throws IOException, GeneralSecurityException;

    String decryptMessage(String message, File privateKeyFile) throws IOException, GeneralSecurityException, InvalidPassphraseException;

    void encryptDocument(File document, File openKey) throws IOException, GeneralSecurityException;

    void decryptDocument(File document, File secretKey) throws IOException, GeneralSecurityException, InvalidPassphraseException;

    void signDocument(File document, File privateKey) throws IOException, GeneralSecurityException, InvalidPassphraseException;

    boolean verifyDocument(File document, File signFile, File publicKey) throws IOException, GeneralSecurityException;
}
