import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class Servercp2 {
    static PrintWriter out = null;
    static ServerSocket welcomeSocket = null;
    static Socket connectionSocket = null;
    static DataOutputStream ClientOut = null;
    static DataInputStream Clientin = null;
    static FileInputStream fileInputStream = null;
    static SecretKey sessionKey;
    static BufferedReader in = null;

    public static void main(String[] args) throws IOException {

        try {
            while (true) {
                init();
                System.out.println("Server running...");
                String request = in.readLine();

                if (request.equals("exit"))
                    System.exit(0);

                else if (request.equals("upload")) {
                    upload();
                }



                else if (request.equals("download")) {
                    download();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(0);
        }

    }

    public static void upload() {
        System.out.println("Client requesting to upload...");
        try {
            int counter = 1;
            while (true) {

                String request = in.readLine();
           
                if (request.equals("We are waiting for server to prove its the server indeed")) {
                    break;
                } else
                    System.out.println("Request rejected.");
            }

            ProtocolServer ProtocolServer = new ProtocolServer("Certificates/certificate_1004422.crt");
            System.out.println("Receiving nonce from Client...");
            Clientin.read(ProtocolServer.getNonce());

            System.out.println("Sending Encrypted nonce to Client...");

            ProtocolServer.encryptNonce();
            ClientOut.write(ProtocolServer.getEncryptedNonce());
            ClientOut.flush();

            while (true) {
                String request = in.readLine();
                System.out.println(request);
                if (request.equals("Checking for a valid certificate")) {
                    ClientOut.write(ProtocolServer.getCertificate());
                    ClientOut.flush();
                    break;
                } else
                    System.out.println("Certificate sharing failed.");
            }

            byte[] encryptedSessionKey;
            String filename = "";
            System.out.println("Client: " + in.readLine());
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            while (connectionSocket.isClosed() == false) {
                int command = Clientin.readInt();
                BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

                if (command == 0) {
                    int nameLength = Clientin.readInt();
                    byte[] nameBytes = new byte[nameLength];
                    Clientin.readFully(nameBytes);
                    filename = new String(nameBytes);
                }

                else if (command == 1) {

                    int encryptedSessionKeySize = Clientin.readInt();
                    encryptedSessionKey = new byte[encryptedSessionKeySize];
                    Clientin.readFully(encryptedSessionKey);// to read the entire buffer.

                    // System.out.println("Session key is of length " + encryptedSessionKey.length);
                    // System.out.println(
                    //         "The encrypted key is  " + Base64.getEncoder().encodeToString(encryptedSessionKey));
                    byte[] sessionKeyBytes = ProtocolServer.decryptFile(encryptedSessionKey);
                    SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
                    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);

                } else if (command == 8) {

                    System.out.println("Receiving file now...");

                    int encryptedFileSize = Clientin.readInt();
                    System.out.println("the file size is " + encryptedFileSize);

                    byte[] encryptedFileBytes = new byte[encryptedFileSize];
                    
                    Clientin.readFully(encryptedFileBytes, 0, encryptedFileSize);
                    // System.out.println(Arrays.toString(encryptedFileBytes));
                    // System.out.println(encryptedFileBytes.length);

                    byte[] result = sessionCipher.doFinal(encryptedFileBytes);

                    FileOutputStream file = new FileOutputStream("recv" + filename); 
                    file.write(result);
                    file.close();

                    System.out.println("Done!");
                    out.println("Transfer complete");


                    counter += 1;
                    Clientin.close();
                    ClientOut.close();
                    connectionSocket.close();
                    welcomeSocket.close();
                }
            }
        } catch (Exception e) {
            System.out.println("UH OH");
            System.exit(0);
        }

    }

    // public static void delete() {
    //     System.out.println("getting deleted");
    //     try {
    //         int counter = 1;
    //         while (true) {

    //             String request = in.readLine();
    //             System.out.println(request);
    //             if (request.equals("Requesting server authentication")) {
    //                 System.out.println("Client: " + request);
    //                 break;
    //             } else
    //                 System.out.println("FAILED");
    //         }

    //         // Initing our certificate
    //         ProtocolServer ProtocolServer = new ProtocolServer("Certificates/certificate_1004422.crt");
    //         /// our nonce is like an ID to show that this convo is new by assigning a new
    //         /// random number to it
    //         System.out.println("Client is sending us the nonce");
    //         Clientin.read(ProtocolServer.getNonce());
    //         System.out.println("Got it. lets encrypt it and send it back");
    //         ProtocolServer.encryptNonce();
    //         System.out.println("done encrypting now sending");
    //         ClientOut.write(ProtocolServer.getEncryptedNonce());

    //         ClientOut.flush();

    //         while (true) {
    //             String request = in.readLine();
    //             System.out.println(request);
    //             if (request.equals("certificate check")) {
    //                 System.out.println("Client: " + request);

    //                 System.out.println("Yup We have sent it to the client");
    //                 ClientOut.write(ProtocolServer.getCertificate());
    //                 ClientOut.flush();
    //                 break;
    //             } else
    //                 System.out.println("FAILED");
    //         }

    //         byte[] encryptedSessionKey;
    //         String filename = "";
    //         System.out.println("Client: " + in.readLine());
    //         Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

    //         while (connectionSocket.isClosed() == false) {

    //             int command = Clientin.readInt();
    //             BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

    //             if (command == 0) {

    //                 int nameLength = Clientin.readInt();// simultaneously receieving the lenght form the client

    //                 byte[] nameBytes = new byte[nameLength]; // to store a byte array with that lenght
    //                 Clientin.readFully(nameBytes);
    //                 filename = new String(nameBytes);
    //                 File file = new File("recv" + filename);

    //                 if (file.delete()) {
    //                     System.out.println("File deleted successfully");
    //                 } else {
    //                     System.out.println("Failed to delete the file");
    //                 }
    //                 System.out.println("Done!");
    //                 out.println("Termination of transferring");

    //                 System.out.println("Send more!");
    //                 counter += 1;
    //                 Clientin.close();
    //                 ClientOut.close();
    //                 connectionSocket.close();
    //                 welcomeSocket.close();

    //             }

    //             else if (command == 1) {

    //                 int encryptedSessionKeySize = Clientin.readInt();
    //                 encryptedSessionKey = new byte[encryptedSessionKeySize];
    //                 Clientin.readFully(encryptedSessionKey);// to read the entire buffer.

    //                 System.out.println("Session key is of length " + encryptedSessionKey.length);
    //                 System.out.println(
    //                         "The encrypted key is  " + Base64.getEncoder().encodeToString(encryptedSessionKey));
    //                 System.out.println("Let us now decrypt it and store it with us");
    //                 byte[] sessionKeyBytes = ProtocolServer.decryptFile(encryptedSessionKey);
    //                 SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
    //                 sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);// decrypting it
    //                 System.out.println("gotcha!");
    //             }

    //         }
    //     } catch (Exception e) {
    //         System.out.println("UH OH");
    //         System.exit(0);
    //     }

    // }

    public static void init() {
        try {
            welcomeSocket = new ServerSocket(4321);

            System.out.println("Server IP: " + welcomeSocket.getInetAddress().getLocalHost().getHostAddress());

            connectionSocket = welcomeSocket.accept();

            Clientin = new DataInputStream(connectionSocket.getInputStream());
            ClientOut = new DataOutputStream(connectionSocket.getOutputStream());

            in = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            out = new PrintWriter(connectionSocket.getOutputStream(), true);
        } catch (Exception e) {
            System.out.println("UGH CRASHED");
            System.exit(0);
        }
    }

    public static void download() {
        System.out.println("getting downloaded");
        try {
            int counter = 1;
            while (true) {

                String request = in.readLine();
                if (request.equals("We are waiting for server to prove its the server indeed")) {
                    System.out.println("Client: " + request);
                    break;
                } else
                    System.out.println("FAILED");
            }

            ProtocolServer ProtocolServer = new ProtocolServer("Certificates/certificate_1004422.crt");
           
            System.out.println("Client is sending us the nonce");
            Clientin.read(ProtocolServer.getNonce());
            System.out.println("Got it. lets encrypt it and send it back");
            ProtocolServer.encryptNonce();
            System.out.println("done encrypting now sending");
            ClientOut.write(ProtocolServer.getEncryptedNonce());

            ClientOut.flush();

            while (true) {
                String request = in.readLine();
                if (request.equals("Checking for a valid certificate")) {
                    System.out.println("Client: " + request);

                    System.out.println("Yup We have sent it to the client");
                    ClientOut.write(ProtocolServer.getCertificate());
                    ClientOut.flush();
                    break;
                } else
                    System.out.println("FAILED");
            }

            byte[] encryptedSessionKey;
            String filename = "";
            System.out.println("Client: " + in.readLine());
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            while (connectionSocket.isClosed() == false) {

                int command = Clientin.readInt();
                BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

                if (command == 0) {

                    int nameLength = Clientin.readInt();

                    byte[] nameBytes = new byte[nameLength];
                    Clientin.readFully(nameBytes);
                    filename = new String(nameBytes);
                    File file = new File("recv" + filename);
                    if (file.exists() == false) {
                        if (file.createNewFile()) {
                            System.out.println("Creating new file...");
                        }

                    }

                    fileInputStream = new FileInputStream(file);
                    byte[] fileByteArray = new byte[(int) file.length()];
                    fileInputStream.read(fileByteArray, 0, fileByteArray.length);
                    fileInputStream.close();
                    System.out.println("before encrypting");
                    sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                    byte[] encryptedFile = sessionCipher.doFinal(fileByteArray);
                    System.out.println("going to send signal 8");
                    ClientOut.writeInt(8);
                    System.out.println("sent signal 8");
                    System.out.println("the length of our encrypted file: " + encryptedFile.length);
                    ClientOut.writeInt(encryptedFile.length);
                    ClientOut.flush();

                    ClientOut.write(encryptedFile, 0, encryptedFile.length);
                    ClientOut.flush();
                    ClientOut.write(encryptedFile, 0, encryptedFile.length);
                    ClientOut.flush();

                    System.out.println("Done!");
                    out.println("Termination of transferring");

                    System.out.println("Send more!");
                    counter += 1;
                    Clientin.close();
                    ClientOut.close();
                    connectionSocket.close();
                    welcomeSocket.close();

                }

                else if (command == 1) {

                    int encryptedSessionKeySize = Clientin.readInt();
                    encryptedSessionKey = new byte[encryptedSessionKeySize];
                    Clientin.readFully(encryptedSessionKey);

                    System.out.println("Session key is of length " + encryptedSessionKey.length);
                    System.out.println(
                            "The encrypted key is  " + Base64.getEncoder().encodeToString(encryptedSessionKey));
                    System.out.println("Let us now decrypt it and store it with us");
                    
                    byte[] sessionKeyBytes = ProtocolServer.decryptFile(encryptedSessionKey);
                    
                    sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
                    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);
                    System.out.println("Finally Done!");
                }

            }
        } catch (Exception e) {
             e.printStackTrace();
            System.exit(0);
        }

    }
}
    class ProtocolServer {
    private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];
    private static byte[] certificate;
    private static InputStream server;
   // private static CertificateFactory cf = null;
   // private static KeyFactory kf = null;
   // private static X509Certificate ServerCert;
   // private static PublicKey publicServerKey;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static Cipher fdcipher;
    private String path = "Certificates/private_key.der";

    public ProtocolServer(String server) throws IOException {
        ProtocolServer.server = new FileInputStream(server);
        try{

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(ProtocolServer.server);
            certificate = CAcert.getEncoded();
            PublicKey publicServerKey = CAcert.getPublicKey();
            privateKey = getPrivateKey(path);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        ProtocolServer.server.close();
    }

    public static PrivateKey getPrivateKey(String filename) throws Exception{
        byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
    public void encryptNonce() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE,privateKey);
        encryptedNonce = cipher.doFinal(nonce);
    }
    public byte[] getNonce(){return nonce;}

    public byte[] getEncryptedNonce(){return encryptedNonce;}

    public byte[] getCertificate() {
        return certificate;
    }

    // CP-1 decryption using private key
    public byte[] decryptFile(byte[] fileByte) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        fdcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        fdcipher.init(Cipher.DECRYPT_MODE,privateKey);
        return fdcipher.doFinal(fileByte);
    }

}