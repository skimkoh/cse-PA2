import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class ServerCP2 {

    private static byte[] nonce = new byte[64];
    private static byte[] encryptedNonce = new byte[256];
    private static final String privateKeyDer = "private_key.der";
    private static final String signedCertificate = "example.org.crt";
    private static X509Certificate ServerCert;

    public static void main(String[] args) throws IOException {

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(4321);

            // Prints IP
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


            // Get nonce from client
            System.out.println("Receiving nonce from client");
            fromClient.read(nonce);
            System.out.println("Nonce received");
            //get private key
            Path privateKeyPath = Paths.get(privateKeyDer);
            byte[] privateKeyByte = Files.readAllBytes(privateKeyPath);

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

            // Encrypt nonce
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE,privateKey);
            encryptedNonce = cipher.doFinal(nonce);

            // Send nonce to client
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


            // Waiting for client to finish verification
            System.out.println("Client: " + stringIn.readLine());

            System.out.println("...Client authenticated. File transfer starting now...");

            String filename = "";
            Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            while (!connectionSocket.isClosed()) {

                int command = fromClient.readInt();
                BufferedInputStream inputStream = new BufferedInputStream(connectionSocket.getInputStream());

                if (command == 0) {
                    // get encrypted session key and decrypt using private key
                    int encryptedSessionKeySize = fromClient.readInt();
                    byte[] encryptedSessionKey = new byte[encryptedSessionKeySize];
                    fromClient.readFully(encryptedSessionKey);

                    System.out.println("Received encrypted session key of size.");
                    System.out.println("Decrypting session key");
                    Cipher f = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    f.init(Cipher.DECRYPT_MODE, privateKey);
                    byte[] sessionKeyBytes = f.doFinal(encryptedSessionKey);
                    SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");
                    sessionCipher.init(Cipher.DECRYPT_MODE, sessionKey);
                }
                else if (command == 1) {
                    int nameLength = fromClient.readInt();
                    byte[] nameBytes = new byte[nameLength];
                    fromClient.readFully(nameBytes);
                    filename = new String(nameBytes);

                } else if (command == 2) {
                    // get file
                    int encryptedFileSize = fromClient.readInt();
                    System.out.println("Receiving file.");

                    byte[] encryptedFileBytes = new byte[encryptedFileSize];
                    fromClient.readFully(encryptedFileBytes, 0, encryptedFileSize);
                    System.out.println(Arrays.toString(encryptedFileBytes));
                    System.out.println(encryptedFileBytes.length);

                    System.out.println("Decrypting file with session key");

                    // decryption of file

                    byte[] result = sessionCipher.doFinal(encryptedFileBytes);
                    FileOutputStream file = new FileOutputStream("recv_" + filename);
                    file.write(result);
                    file.close();

                    // done
                    stringOut.println("...Server: File transfer done.");
                    System.out.println("Closing connections");

                    fromClient.close();
                    toClient.close();
                    connectionSocket.close();
                }
            }
        } catch (Exception e) {e.printStackTrace();}

    }
}