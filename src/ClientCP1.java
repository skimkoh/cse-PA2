import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;

public class ClientCP1 {

    private static byte[] encryptedNonce = new byte[256];
    private static final String CACertFile = "CA.crt";
    private static X509Certificate ServerCert;

    public static void main(String[] args) {

        String filename = "rr.txt";
    	if (args.length > 0) filename = args[0];

    	String serverAddress = "localhost";
    	if (args.length > 1) serverAddress = args[1];

        int port = 4321;
    	if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;

        long timeStarted = System.nanoTime();

        try {

            System.out.println("Establishing connection to server...");

            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);

            // data channels
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());

            // string channels
            BufferedReader stringIn = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter stringOut = new PrintWriter(clientSocket.getOutputStream(), true);

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

            // get public key from CA
            InputStream in = new FileInputStream(CACertFile);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate CACert = (X509Certificate) certificateFactory.generateCertificate(in);
            PublicKey CAPublicKey = CACert.getPublicKey();


            // ask for cert, gets signed cert. 
            System.out.println("Requesting for signed certificate from server");
            stringOut.println("...Client: Give me your certificate signed by CA");

            ServerCert = (X509Certificate) certificateFactory.generateCertificate(fromServer);

            System.out.println("Certificate received");


            // validate cert with CA public key
            ServerCert.checkValidity();
            ServerCert.verify(CAPublicKey);
            System.out.println("Certificate verified.");

            // Get public key
            PublicKey serverPublicKey = ServerCert.getPublicKey();

            // create cipher object
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, serverPublicKey);

            // decrypt nonce
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


            System.out.println("Server authentication successful.");

            // Open the file
            fileInputStream = new FileInputStream(filename);
            bufferedFileInputStream = new BufferedInputStream(fileInputStream);

            timeStarted = System.nanoTime();

            // file size
            int fileSize = fileInputStream.available();
            toServer.writeInt(fileSize);
            toServer.flush();

            System.out.println("Sending file name...");
            // Send the filename
            toServer.writeInt(0);
            toServer.writeInt(filename.getBytes().length);
            toServer.write(filename.getBytes());
            toServer.flush();


            byte [] fromFileBuffer = new byte[117];

            int count = 0;

            // Send the encrypted file
            System.out.println("Sending file...");
            for (boolean fileEnded = false; !fileEnded;) {

                numBytes = bufferedFileInputStream.read(fromFileBuffer);

                // encrypt
                Cipher encipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                encipher.init(Cipher.ENCRYPT_MODE,serverPublicKey);
                byte[] encryptedfromFileBuffer = encipher.doFinal(fromFileBuffer);
                count++;
                fileEnded = numBytes < fromFileBuffer.length;
                int encryptedNumBytes = encryptedfromFileBuffer.length;

                toServer.writeInt(1);
                toServer.writeInt(encryptedNumBytes);
                toServer.writeInt(numBytes);
                toServer.write(encryptedfromFileBuffer);
                toServer.flush();
            }

            System.out.println(stringIn.readLine());

            System.out.println("Closing connections");
            bufferedFileInputStream.close();
            fileInputStream.close();


        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        double ms = timeTaken/1000000.0;
        System.out.println("File transfer took: " + ms + "ms");
    }


}

