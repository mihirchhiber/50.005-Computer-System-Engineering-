

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.io.*;
import java.net.Socket;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;
public class Clientcp2 {

    static  BufferedReader in = null;
    static  DataOutputStream ServerOutput = null;
    static  FileInputStream fileInputStream = null;
    static  PrintWriter out = null;
    static  Socket clientSocket = null;
    static  DataInputStream ServerInput = null;
    static  String filename;
    static  String serverIP;
    public static void main(String[] args) {

         serverIP = "192.168.56.1";
        String command ;
        while(true){
        	try{
        		
                System.out.println("Enter upload/download validfilename");
                Scanner scanner = new Scanner(System.in);
                
                command = scanner.nextLine();
                if(command.equals("exit")){
                    init();
                    out.println("exit");
                    System.exit(0);
                }
                
                if(command.split(" ",4).length <2)
                    continue;
                
                    filename = command.split(" " , 4)[1];
                command  = command.split(" " , 4)[0];

                File tmpDir = new File(filename);
                boolean exists = tmpDir.exists();
                
                if (command.equals("download")) exists = true;
        
                if(exists == false ||(!command.equals("upload") && !command.equals("download")  )) continue;
                
                init();
                System.out.println("Process: " + command + " " + filename);

                if(command.equals("upload")){
                    System.out.println("Uploading file to Server now...");
                    out.println("upload");
                    upload();
                }
                
                
                    else{out.println("download");
                    System.out.println("gotcha");
                    download();
                }
         }
        catch(Exception e){
            e.printStackTrace();
            System.exit(0);
        }
        
    }
}
    public static void upload(){
        if(filename == null){
            Scanner scanner = new Scanner(System.in);
            filename = scanner.nextLine();
        }
        
        long timeStarted = 0;
        try {
            ProtocolClient ProtocolClient = new ProtocolClient("Certificates/cacsertificate.crt");

            out.println("We are waiting for server to prove its the server indeed");
            System.out.println("We are going to validate the certicate (AP)");

   
            System.out.println("Nonce creation");
            ProtocolClient.generateNonce();
            System.out.println("Sending our nonce to the server which it will encrypt and send back");
            ServerOutput.write(ProtocolClient.getNonce());
            ServerInput.read(ProtocolClient.getEncryptedNonce());
            System.out.println("Gotten the encryptednonce");

         
            System.out.println("Now we ask the server for its certificate (AP)");
            out.println("Checking for a valid certificate");


            ProtocolClient.getCertificate(ServerInput); //Using ServerInput.read(ProtocalClinet.getCertifcate) did not workhmm
            System.out.println("Certificate is being validated");
            ProtocolClient.verifyCert();
            System.out.println("Certificate validated");
            System.out.println("Now to very the server");
            ProtocolClient.getPublicKey();
            byte[] decryptedNonce = ProtocolClient.decryptNonce(ProtocolClient.getEncryptedNonce());
//we basically have to now decryt the encyrpted nonce and then check if the nonce we sent equals the nonce we got. This implies that the server indeed sneds a valid public key and is legit

            if (ProtocolClient.validateNonce(decryptedNonce)){
                
                out.println("SUCCESSFULY VERIFIED");
                System.out.println("THe Server has been successfully verified");
            } else{
                System.out.println("ERROR FAILED");
                System.out.println("tERMINATING ALL THE CONNECTIONS");
                ServerOutput.close();
                ServerInput.close();
                clientSocket.close();
            }

            System.out.println("CP2 BASED TRANSFER");

//Create a Cipher similar to the lab acitivity
            SecretKey seshKey = KeyGenerator.getInstance("AES").generateKey();
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            sessionCipher.init(Cipher.ENCRYPT_MODE, seshKey);

            //encryping sesh key with the public key server sent
            byte[] encryptedseshKey = ProtocolClient.encryptFile(seshKey.getEncoded());
            //System.out.println(Base64.getEncoder().encodeToString(encryptedseshKey));

            BufferedOutputStream outputStream = new BufferedOutputStream(ServerOutput);

            timeStarted = System.nanoTime();

         
            ServerOutput.writeInt(1);
            ServerOutput.writeInt(encryptedseshKey.length);
            ServerOutput.flush();

            outputStream.write(encryptedseshKey, 0, encryptedseshKey.length);
            outputStream.flush();

            System.out.println("Encrypted Session key has been sent");
            File file = new File(filename);
            fileInputStream = new FileInputStream(file);
            byte[] fileByteArray = new byte[(int)file.length()];
            fileInputStream.read(fileByteArray, 0, fileByteArray.length);//  storing in filebytearray
            fileInputStream.close();
            ServerOutput.writeInt(0);
            ServerOutput.writeInt(filename.getBytes().length); //send this similar to lab 5 as a byte array
            ServerOutput.flush();

            outputStream.write(filename.getBytes());
            outputStream.flush();
            byte[] encryptedFile = sessionCipher.doFinal(fileByteArray); //encrypting file
          //  System.out.println(Base64.getEncoder().encodeToString(encryptedFile));
            ServerOutput.writeInt(8);
          //  System.out.println("the length of our encrypted file: " + encryptedFile.length);
            ServerOutput.writeInt(encryptedFile.length);
            ServerOutput.flush();

           
            ServerOutput.write(encryptedFile, 0, encryptedFile.length);
            ServerOutput.flush();

            while (true) {
                String end = in.readLine();
                System.out.println(end);
                if (end.equals("Transfer complete")){
                    System.out.println("Server: " + end); //communciation ending
                    break;
                }
                else
                    System.out.println("End request failed...");
            }

            System.out.println("Type another file name");
            fileInputStream.close();

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
filename =null;
 
    }
    
    public static void init() {
        try {
            clientSocket = new Socket(serverIP, 4321);

            ServerOutput = new DataOutputStream(clientSocket.getOutputStream());
            ServerInput = new DataInputStream(clientSocket.getInputStream());

            out = new PrintWriter(clientSocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // public static void delete(){
    //     System.out.println("going to delete");

    //     if (filename == null) {
    //         Scanner scanner = new Scanner(System.in);
    //         filename = scanner.nextLine();

    //     }

    //     long timeStarted = 0;
    //     try {
    //         ProtocolClient ProtocolClient = new ProtocolClient("Certificates/cacsertificate.crt");

    //         out.println("Requesting server authentication");
    //         System.out.println("We are going to validate the certicate (AP)");
    //         ProtocolClient.generateNonce();
    //         System.out.println("Sending our nonce to the server which it will encrypt and send back");
    //         ServerOutput.write(ProtocolClient.getNonce());
    //         ServerInput.read(ProtocolClient.getEncryptedNonce());
    //         System.out.println("Gotten the encryptednonce");

    //         System.out.println("Authenticating Server Identity...");
    //         out.println("certificate check");

    //         ProtocolClient.getCertificate(ServerInput);
    //         System.out.println("Certificate is being validated");
    //         ProtocolClient.verifyCert();
    //         System.out.println("Certificate validated");
    //         System.out.println("Now to very the server");
    //         ProtocolClient.getPublicKey();
    //         byte[] decryptedNonce = ProtocolClient.decryptNonce(ProtocolClient.getEncryptedNonce());

    //         if (ProtocolClient.validateNonce(decryptedNonce)) {

    //             out.println("SUCCESSFULY VERIFIED");
    //             System.out.println("THe Server has been successfully verified");
    //         } else {
    //             System.out.println("ERROR FAILED");
    //             System.out.println("tERMINATING ALL THE CONNECTIONS");
    //             ServerOutput.close();
    //             ServerInput.close();
    //             clientSocket.close();
    //         }

    //         System.out.println("CP2 BASED TRANSFER");

    //         SecretKey seshKey = KeyGenerator.getInstance("AES").generateKey();
    //         Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
    //         sessionCipher.init(Cipher.ENCRYPT_MODE, seshKey);

    //         byte[] encryptedseshKey = ProtocolClient.encryptFile(seshKey.getEncoded());
    //         System.out.println(Base64.getEncoder().encodeToString(encryptedseshKey));

    //         BufferedOutputStream outputStream = new BufferedOutputStream(ServerOutput);
    //         timeStarted = System.nanoTime();
    //         ServerOutput.writeInt(1);
    //         ServerOutput.writeInt(encryptedseshKey.length);
    //         ServerOutput.flush();

    //         outputStream.write(encryptedseshKey, 0, encryptedseshKey.length);
    //         outputStream.flush();

    //         System.out.println("Encrypted Session key has been sent");
    //         File file = new File(filename);

    //         ServerOutput.writeInt(0);
    //         ServerOutput.writeInt(filename.getBytes().length); 
    //         ServerOutput.flush();

    //         outputStream.write(filename.getBytes());
    //         outputStream.flush();

    //         while (true) {
    //             String end = in.readLine();
    //             System.out.println(end);
    //             if (end.equals("Termination of transferring")) {
    //                 System.out.println("Server: " + end);
    //                 break;
    //             } else
    //                 System.out.println("End request failed...");
    //         }
    //         System.out.println("Type another file name");
    //         ;

    //     } catch (Exception e) {
    //         e.printStackTrace();
    //     }

    //     long timeTaken = System.nanoTime() - timeStarted;
    //     System.out.println("Program took: " + timeTaken / 1000000.0 + "ms to run");
    //     filename = null;

    // }

    public static void download(){
    	System.out.println("going to donwload");

    	int counter=0;
        if(filename ==null){
            Scanner scanner = new Scanner(System.in);
            filename = scanner.nextLine();
        }
        long timeStarted = 0;
        try {
            ProtocolClient ProtocolClient = new ProtocolClient("Certificates/cacsertificate.crt");

            out.println("We are waiting for server to prove its the server indeed");
            System.out.println("We are going to validate the certicate (AP)");

   
            System.out.println("Nonce creation");
            ProtocolClient.generateNonce();
            System.out.println("Sending our nonce to the server which it will encrypt and send back");
            ServerOutput.write(ProtocolClient.getNonce());
            ServerInput.read(ProtocolClient.getEncryptedNonce());
            System.out.println("Gotten the encryptednonce");

         
            System.out.println("Now we ask the server for its certificate (AP)");
            out.println("Checking for a valid certificate");


            ProtocolClient.getCertificate(ServerInput); //Using ServerInput.read(ProtocalClinet.getCertifcate) did not workhmm
            System.out.println("Certificate is being validated");
            ProtocolClient.verifyCert();
            System.out.println("Certificate validated");
            System.out.println("Now to very the server");
            ProtocolClient.getPublicKey();
            byte[] decryptedNonce = ProtocolClient.decryptNonce(ProtocolClient.getEncryptedNonce());

            if (ProtocolClient.validateNonce(decryptedNonce)){
                
                out.println("SUCCESSFULY VERIFIED");
                System.out.println("THe Server has been successfully verified");
            } else{
                System.out.println("ERROR FAILED");
                System.out.println("tERMINATING ALL THE CONNECTIONS");
                ServerOutput.close();
                ServerInput.close();
                clientSocket.close();
            }

            System.out.println("CP2 BASED TRANSFER");

//Create a Cipher similar to the lab acitivity
            SecretKey seshKey = KeyGenerator.getInstance("AES").generateKey();
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            sessionCipher.init(Cipher.ENCRYPT_MODE, seshKey);

            //encryping sesh key with the public key server sent
            byte[] encryptedseshKey = ProtocolClient.encryptFile(seshKey.getEncoded());
            System.out.println(Base64.getEncoder().encodeToString(encryptedseshKey));

            BufferedOutputStream outputStream = new BufferedOutputStream(ServerOutput);
//We could use the PrintWRiter however we using BUfferedReader as we need the output to stay in the buffer to be read as and when

            // begin clocking the file transfer
            timeStarted = System.nanoTime();

         
            ServerOutput.writeInt(1);
            ServerOutput.writeInt(encryptedseshKey.length);
            ServerOutput.flush();

            outputStream.write(encryptedseshKey, 0, encryptedseshKey.length);
            outputStream.flush();

            System.out.println("Encrypted Session key has been sent");
            
            ServerOutput.writeInt(0);
            ServerOutput.writeInt(filename.getBytes().length); //send this similar to lab 5 as a byte array
            ServerOutput.flush();
            
            outputStream.write(filename.getBytes());
            outputStream.flush();
            System.out.println("before the int is read");

            int signal =  ServerInput.readInt();
            System.out.println("signal is "+signal);
            if (signal == 8) {
                   
                    System.out.println("Going to receieve the file ");
            

                    int encryptedFileSize = ServerInput.readInt();
                    System.out.println("the file size is " + encryptedFileSize);

                    byte[] encryptedFileBytes = new byte[encryptedFileSize];
                    ServerInput.readFully(encryptedFileBytes, 0, encryptedFileSize);
                    System.out.println(Arrays.toString(encryptedFileBytes));
                    System.out.println(encryptedFileBytes.length);

                    System.out.println("UH OH it is encrypted. Let us decrypt it coz we got public key");
                    sessionCipher.init(Cipher.DECRYPT_MODE, seshKey);
                    byte[] result = sessionCipher.doFinal(encryptedFileBytes);
                

                    FileOutputStream file = new FileOutputStream("RECIEVED_" + filename); //creating output file
                    file.write(result);
                    file.close();

                    System.out.println("Done!");
                   // out.println("Termination of transferring");

                   
                    System.out.println("Send more!");
                    counter+=1;
                    ServerOutput.close();
                    ServerInput.close();
                    
                    System.out.println("downloaded!");
                }

           

            System.out.println("Type another file name");
            fileInputStream.close();

        }

         catch (Exception e) {System.out.println("Saved as RECIEVED_<filename>");}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
filename =null;
 
    }
}

 class ProtocolClient {
    private static InputStream CA;
    private static CertificateFactory cf = null;
    private static X509Certificate CAcert;
    private static X509Certificate ServerCert;
    private static PublicKey CAkey;
    private static PublicKey serverKey;

    private static byte[] nonce = new byte[32];
    private static byte[] encryptedNonce = new byte[128];

    private static Cipher dcipher;
    private static Cipher fcipher;

    public ProtocolClient(String CA) throws IOException {
        ProtocolClient.CA = new FileInputStream(CA);

        try {
            cf = CertificateFactory.getInstance("X.509");

            // Get public key from CA certificate
            CAcert =(X509Certificate)cf.generateCertificate(ProtocolClient.CA);
            CAkey = CAcert.getPublicKey();

        } catch (CertificateException e) {
            e.printStackTrace();
        }

        ProtocolClient.CA.close();
    }

    public void getCertificate(InputStream certificate) throws CertificateException {
        // Get signed server certificate
        ServerCert =(X509Certificate)cf.generateCertificate(certificate);
    }

    public void getPublicKey() {
        // Get server public key from certificate
        serverKey = ServerCert.getPublicKey();
    }

    // Verify signed certificate using CA's public key
    public void verifyCert(){
        try {
            ServerCert.checkValidity();
            ServerCert.verify(CAkey);

        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

    // Generate nonce
    public void generateNonce(){
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);
    }

    // Decrypt encrypted nonce with public key
    public byte[] decryptNonce(byte[] encryptedNonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        dcipher.init(Cipher.DECRYPT_MODE,serverKey);
        return dcipher.doFinal(encryptedNonce);
    }

    // Checks that decrypted nonce equals to original nonce
    public boolean validateNonce(byte[] decryptedNonce){
        return Arrays.equals(nonce,decryptedNonce);
    }

    public byte[] getEncryptedNonce(){
        return encryptedNonce;
    }

    public byte[] getNonce(){return nonce;}

    // CP-1 encryption using public key
    public byte[] encryptFile(byte[] fileByte) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        fcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        fcipher.init(Cipher.ENCRYPT_MODE,serverKey);
        return fcipher.doFinal(fileByte);
    }

}

   

