import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class ServerCP1 {

    private static byte[] nonce = new byte[64];
    private static byte[] encryptedNonce = new byte[256];
    private static final String privateKeyDer = "private_key.der";
    private static final String signedCertificate = "example.org.crt";
    private static X509Certificate ServerCert;


    public static void main(String[] args) {

        int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;


        try {
            welcomeSocket = new ServerSocket(port);

            System.out.println("Server IP: " + welcomeSocket.getInetAddress().getLocalHost().getHostAddress());
            System.out.println("...Server connected, waiting for client...");
            connectionSocket = welcomeSocket.accept();
            System.out.println("...Connection confirmed...");

            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());


            BufferedReader stringIn = new BufferedReader(new InputStreamReader(connectionSocket.getInputStream()));
            PrintWriter stringOut = new PrintWriter(connectionSocket.getOutputStream(), true);

            System.out.println(stringIn.readLine());
            System.out.println("Hello, this is SecStore.");


            // get nonce from client
            System.out.println("Receiving nonce from client");
            fromClient.read(nonce);
            System.out.println("Nonce received");

            //get private key
            Path privateKeyPath = Paths.get(privateKeyDer);
            byte[] privateKeyByte = Files.readAllBytes(privateKeyPath);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // encrypt nonce
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            encryptedNonce = cipher.doFinal(nonce);

            // send nonce back
            System.out.println("Sending encrypted nonce to client");
            toClient.write(encryptedNonce);
            toClient.flush();

            // send cert
            System.out.println(stringIn.readLine());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ServerCert =(X509Certificate)cf.generateCertificate(new FileInputStream(signedCertificate));
            byte[] certificate = ServerCert.getEncoded();
            toClient.write(certificate);
            toClient.flush();
            System.out.println("Sending signed certificate to client");

            System.out.println("Client: " + stringIn.readLine());

            // Starts file transfer
            System.out.println("AP completes. Receiving file...");


            // Get file size from client
            int fileSize = fromClient.readInt();
            System.out.println(fileSize);
            int size = 0;

            int count = 0;

            while (size < fileSize) {

                int packetType = fromClient.readInt();

                // If the packet is for transferring the filename
                if (packetType == 0) {

                    System.out.println("Receiving file...");

                    int numBytes = fromClient.readInt();
                    byte [] filename = new byte[numBytes];
                    fromClient.read(filename);

                    fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
                    bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                    // If the packet is for transferring a chunk of the file
                } else if (packetType == 1) {
                    count++;
                    int numBytes = fromClient.readInt();
                    int decryptedNumBytes = fromClient.readInt();
                    size+=decryptedNumBytes;

                    byte[] block = new byte[numBytes];
                    fromClient.read(block);

                    // Decrypt each 128 bytes
                    Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    cipher1.init(Cipher.DECRYPT_MODE,privateKey);
//                    byte[] decryptedBlock = serverProtocol.decryptFile(block);
                    byte[] decryptedBlock = cipher1.doFinal(block);

                    if (numBytes > 0){
                        bufferedFileOutputStream.write(decryptedBlock, 0, decryptedNumBytes);
                        bufferedFileOutputStream.flush();
                    }
                }
            }

            // done
            stringOut.println("...Server: File transfer done.");
            System.out.println("Closing connection...");
            bufferedFileOutputStream.close();
            fileOutputStream.close();

            fromClient.close();
            toClient.close();
            connectionSocket.close();

        }catch (Exception e){
            e.printStackTrace();
        }

    }

}
