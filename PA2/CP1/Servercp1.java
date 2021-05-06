
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.concurrent.TimeUnit;


public class Servercp1 {

    public static void main(String[] args) {

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        BufferedReader inputReader = null;

        PrintWriter out = null;

        try {
            welcomeSocket = new ServerSocket(4321);

            // Prints IP
            System.out.println("Server IP: " + welcomeSocket.getInetAddress().getLocalHost().getHostAddress());

            connectionSocket = welcomeSocket.accept();

            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());

            inputReader = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));

            out = new PrintWriter(connectionSocket.getOutputStream(), true);

            while (true){
                String request = inputReader.readLine();
                if (request.equals("Requesting authentication...")){
                    System.out.println("Client: " + request);
                    break;
                }
                else
                    System.out.println("Request failed...");
            }

            // Set up protocol
            ProtocolServer serverProtocol = new ProtocolServer("Certificates/certificate_1004422.crt");

            // Get nonce from client
            System.out.println("Getting nonce from client...");
            fromClient.read(serverProtocol.getNonce());
            System.out.println("Nonce received");

            // Encrypt nonce
            System.out.println("Encrypting nonce...");
            serverProtocol.encryptNonce();
            

            // Send nonce to client
            System.out.println("Sending encrypted nonce to client...");
            toClient.write(serverProtocol.getEncryptedNonce());
            toClient.flush();
            
            System.out.println(serverProtocol.getEncryptedNonce());

            // Receive certificate request from client
            while (true){
                String request = inputReader.readLine();
                if (request.equals("Request certificate...")){
                    System.out.println("Client: " + request);

                    // Send certificate to client
                    System.out.println("Sending certificate to client...");
                    toClient.write(serverProtocol.getCertificate());
                    toClient.flush();
                    break;
                }
                else
                    System.out.println("Request failed...");
            }

            // Waiting for client to finish verification
            System.out.println("Client: " + inputReader.readLine());

            

            int count = 0;

            while(true){
                int packetType = fromClient.readInt();
                if  (packetType == -1){
                    // System.out.println(packetType);
                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    fromClient.read(filename);
                    count = Integer.parseInt(new String(filename, 0, numBytes));
                    break;
                }
            }

            // Starts file transfer
            System.out.println("AP completes. Receiving file...");
            TimeUnit.MILLISECONDS.sleep(2000);
            // Get file size from client
            int fileSize;
            int size;

            
            System.out.println(count);


            while(count!=0){
                fileSize = fromClient.readInt();
                System.out.println(fileSize);
                size = 0;
                System.out.println(count);
            while (size < fileSize) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {
                    count--;

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    fromClient.read(filename);

                    fileOutputStream = new FileOutputStream("recv" + new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    int numBytes = fromClient.readInt();
                    int decryptedNumBytes = fromClient.readInt();
                    size+=decryptedNumBytes;

                    byte [] block = new byte[numBytes];
                    fromClient.read(block);

                    // Decrypt each 128 bytes
                    byte[] decryptedBlock = serverProtocol.decryptFile(block);

                    if (numBytes > 0){
                        bufferedFileOutputStream.write(decryptedBlock, 0, decryptedNumBytes);
                        bufferedFileOutputStream.flush();
                    }
                }
            }
        }

            // Indicate end of transfer to client
            System.out.println("Transfer finished");
            out.println("Ending transfer...");

            // Close connection
            System.out.println("Closing connection...");
            bufferedFileOutputStream.close();
            fileOutputStream.close();

            fromClient.close();
            toClient.close();
            connectionSocket.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}

    class ProtocolServer {
    private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];
    private static byte[] certificate;
    private static InputStream server;
    private static CertificateFactory cf = null;
    private static KeyFactory kf = null;
    private static X509Certificate ServerCert;
    private static PublicKey publicServerKey;
    private static PrivateKey privateKey;
    private static Cipher cipher;
    private static Cipher fdcipher;
    private String path = "Certificates/private_key.der";

    public ProtocolServer(String server) throws IOException {
        this.server = new FileInputStream(server);
        try{

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(this.server);
            certificate = CAcert.getEncoded();
            publicServerKey = CAcert.getPublicKey();
            privateKey = getPrivateKey(path);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        this.server.close();
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


