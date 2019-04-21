import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.*;
import java.util.Arrays;

public class Server {
    private final int HOST_PORT = 1234; // just a number that represents which application to run
    private final String ASYMMETRIC_ALGO = "RSA"; // algorithm of asymmetric encryption, that is used to exchange key
    private final int KEY_SIZE = 2048; // the key size for RSA
    private byte[] clientEncryptedSecretKey;
    private String clientSecretKey; // received SecretKey from Client(Bob) by using RSA algorithm
    private ServerSocket serverSocket; // waits for clients request (when new Socket() is called)
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public Server() {
        try {
            serverSocket = new ServerSocket(HOST_PORT); // starts server
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public void establishConnection() throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        byte[] clientMessage = null;
        System.out.println("Server is running!");
        System.out.println("Waiting for a client...");
        // In this loop, all the connections made by clients will be accepted
        while (!decryptMessage(clientMessage).equalsIgnoreCase("exit")) {
            try {
                // Waits for a client to connect
                Socket socket = serverSocket.accept();

                // Getting input from the connected client and printing in to the screen
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                // getOutputStream() method is used to send the output through the socket
                // the same applies to input
                clientMessage = (byte[]) input.readObject();

                System.out.println("Alice: " + decryptMessage(clientMessage));
            } catch (NullPointerException | IOException | ClassNotFoundException ioe) {
                ioe.printStackTrace();
            }
        }

    }

    public void generateKeys() throws NoSuchAlgorithmException {
        // KeyPairGenerator is java built-in class, that generated pair of keys with given operation/algorithm name
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ASYMMETRIC_ALGO);
        keyPairGenerator.initialize(KEY_SIZE);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
    }

    public void sendPublicKey() {
        try {
            // waits until the Client(Alice) connects to the Server(Bob)
            Socket socket = serverSocket.accept();
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            oos.writeObject(this.publicKey);

            oos.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void receiveSecretKey() {
        try {
            // here Server(Bob) is waining for Client(Alice) to send her encrypted SecretKey
            Socket socket = serverSocket.accept();
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            this.clientEncryptedSecretKey = (byte[]) ois.readObject();
            decryptSecretKeyRSA();

            ois.close();
            socket.close();
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
    }

    public void decryptSecretKeyRSA() {
        try {
            // Decrypts the SecretKey from client with own PrivateKey
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedSecretKey = cipher.doFinal(clientEncryptedSecretKey);

            this.clientSecretKey = new String(decryptedSecretKey);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public String decryptMessage(byte[] inputMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        if (inputMessage != null) {
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            byte[] digested = sha.digest(clientSecretKey.getBytes());
            digested = Arrays.copyOf(digested, 16);
            // We are using SHA-1 hash algorithm to  make our string secret key an
            // array of bytes of size 16 bytes or 128bits =)

            SecretKeySpec secretKeySpec = new SecretKeySpec(digested, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            byte[] decryptedInputMessage = cipher.doFinal(inputMessage);

            return new String(decryptedInputMessage);
        }
        return new String("Null input buffer!");
    }

    public void closeServer() {
        try {
            // closes the server
            this.serverSocket.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    public static void main(String args[]) throws IOException {
        try {
            Server bob = new Server();
            bob.generateKeys();
            bob.sendPublicKey();
            bob.receiveSecretKey();
            bob.establishConnection();
            bob.closeServer();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }
}