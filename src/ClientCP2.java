import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class ClientCP2 {

    private static byte[] encryptedNonce = new byte[256];
    private static final String CACertFile = "CA.crt";
    private static X509Certificate ServerCert;

    public static void main(String[] args) {

        String filename = args[0];//String filename = "audio.mp3";
        String serverIP = args[1];

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
        FileInputStream fileInputStream = null;

        long timeStarted = 0;

        try {

            System.out.println("...Connecting to server...");
            clientSocket = new Socket(serverIP, 4321);

            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            // string channels
            BufferedReader stringIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter stringOut = new PrintWriter(clientSocket.getOutputStream(), true);

            // Set up protocol

            stringOut.println("...Client: Hello SecStore, please prove your identity");
            System.out.println("Requesting for server identity");

            // generate nonce
            SecureRandom secureRandom = new SecureRandom();
            byte[] nonce = new byte[64];
            secureRandom.nextBytes(nonce);

            // send nonce to server
            System.out.println("Sending nonce to server");
            toServer.write(nonce);

            // get encrypted nonce from server
            fromServer.read(encryptedNonce);
            System.out.println("Received encrypted nonce from server");

            // Send certificate request to server
            System.out.println("Requesting certificate from server");
            stringOut.println("Request certificate");

            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            ServerCert = (X509Certificate) certificateFactory.generateCertificate(fromServer);

            System.out.println("Certificate received");
            ServerCert.checkValidity();
            System.out.println("Certificate validated");
            // Get public key
            PublicKey serverPublicKey = ServerCert.getPublicKey();


            // Decrypt encrypted nonce
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            byte[] decryptedNonce = cipher.doFinal(encryptedNonce);

            if(Arrays.equals(nonce,decryptedNonce )){
                System.out.println("Server verified");
                stringOut.println("Server verified");

            }else{
                System.out.println("Bye!");
                System.out.println("Closing all connections...");
                toServer.close();
                fromServer.close();
                clientSocket.close();
            }


            System.out.println("...Server authenticated. File transfer starting now...");

            // init the cipher
            SecretKey sessionKey = KeyGenerator.getInstance("AES").generateKey();
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);

            // encrypt the session key
            Cipher f = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            f.init(Cipher.ENCRYPT_MODE,serverPublicKey);
            byte[] encryptedSessionKey = f.doFinal(sessionKey.getEncoded());

            BufferedOutputStream outputStream = new BufferedOutputStream(toServer);

            timeStarted = System.nanoTime();

            // notify server that the session key is coming
            toServer.writeInt(0);
            toServer.writeInt(encryptedSessionKey.length);
            toServer.flush();

            outputStream.write(encryptedSessionKey, 0, encryptedSessionKey.length);
            outputStream.flush();

            System.out.println("Sent encrypted session key");

            // Open the file
            File file = new File(filename);
            fileInputStream = new FileInputStream(file);

            // set up buffer and read the file into it
            byte[] fileByteArray = new byte[(int)file.length()];
            fileInputStream.read(fileByteArray, 0, fileByteArray.length);
            fileInputStream.close();

            // send the file name as encrypted byte array
            toServer.writeInt(1);
            toServer.writeInt(filename.getBytes().length);
            toServer.flush();

            outputStream.write(filename.getBytes());
            outputStream.flush();

            // encrypt the file with the session key
            //byte[] encryptedFile = clientProtocol.encryptFile(sessionCipher, fileByteArray);
            byte[] encryptedFile = sessionCipher.doFinal(fileByteArray);

            // tell the server the encrypted file is coming and send it
            toServer.writeInt(2);
            System.out.println("Writing length: " + encryptedFile.length);
            toServer.writeInt(encryptedFile.length);
            toServer.flush();

            //outputStream = new BufferedOutputStream(toServer);
            toServer.write(encryptedFile, 0, encryptedFile.length);
            toServer.flush();

            //done
            System.out.println("Closing connections");
            fileInputStream.close();

        } catch (Exception e) {e.printStackTrace();}

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }
}
