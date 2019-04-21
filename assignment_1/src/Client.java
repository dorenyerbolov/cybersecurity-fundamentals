import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Arrays;

public class Client {
    private final String HOST_IP = "127.0.0.1"; // IP address of the host/server
    private final String ASYMMETRIC_ALGO = "RSA"; // algorithm of asymmetric encryption, that is used to exchange key
    private final String SYMMETRIC_ALGO = "AES"; // algorithm of symmetric encryption, that is used to encrypt message
    private final String HASH_ALGO = "SHA-1"; // we've used hash function in order to convert our secret key(string)
    // to the value of a fixed bit size - 128 bits in our case
    private final String SECRET_KEY = "victory";
    private final int HOST_PORT = 1234; // just a number that represents which application to run
    private PublicKey serverPublicKey; // Public Key that was sent from the Server(Bob), to encrypt the secret key and
    // send it back to the Server(Bob), so that Server(bob) will get secret key for further message decryption
    private byte[] encryptedSecretKey;
    private boolean isConnected;

    public Client() {
        isConnected = false;
    }

    public void encryptSecretKeyRSA() { // this method is used in order to encrypt SecretKey by using RSA algo
        try {
            Cipher cipher = Cipher.getInstance(ASYMMETRIC_ALGO); // we used class Cipher from crypto library
            // the class itself provides functionality of a crypto cipher. it accepts the name of the algorithm to get
            // the desired functionality
            cipher.init(Cipher.ENCRYPT_MODE, serverPublicKey); // initialized the cipher with encryption mode and
            // public key that was derived from the Server(Bob)

            this.encryptedSecretKey = cipher.doFinal(SECRET_KEY.getBytes()); // basically, encrypts data(secret key in this context)
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
    }

    public void establishConnection() { // Establishing socket connection between Client(Alice) and Server(Bob)
        String greeting, outputMessage = "";
        System.out.println("Welcome, Alice!\nWrite down \"exit\" to quit the program");

        while (!outputMessage.equalsIgnoreCase("exit")) {
            try {
                // Creating a connection to the server socket
                Socket socket = new Socket(HOST_IP, HOST_PORT);

                if (!isConnected) {
                    System.out.println("Connection established");
                }
                isConnected = true;

                // Input and output streams to send messages to the server
                BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
                ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());

                // Basically, reading and writing to the streams
                outputMessage = input.readLine();
                output.writeObject(encryptMessage(outputMessage));
            } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                e.printStackTrace();
            }
        }
    }

    public void receivePublicKey() {
        try {
            // this method creates connection to the Server(Bob) socket it order to get his PublicKey
            // which is used to encrypt SecretKey and send back to Server(Bob)
            Socket socket = new Socket(HOST_IP, HOST_PORT);
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            this.serverPublicKey = (PublicKey) ois.readObject();

            ois.close();
            socket.close();
        } catch (IOException | ClassNotFoundException ioe) {
            ioe.printStackTrace();
        }
    }

    public void sendSecretKey() {
        try {
            // this method again connects to the Server(Bob) socket, but this time we are sending already encrypted
            // SecretKey to the Server(Bob) so that in future he will be able to decrypt messages
            Socket socket = new Socket(HOST_IP, HOST_PORT);
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
            oos.writeObject(this.encryptedSecretKey);

            oos.close();
            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public byte[] encryptMessage(String outputMessage) throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        // in general, this method encrypts the message from Client(Alice) by using java built-in utilities
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] digested = sha.digest(SECRET_KEY.getBytes());
        digested = Arrays.copyOf(digested, 16);
        // We are using SHA-1 hash algorithm to  make our string secret key an
        // array of bytes of size 16 bytes or 128bits =)(we are trimming its 160bit output to 128bit)

        // the SecretKeySpec is basically the SecretKey, but here we are providing algorithm name to define
        // that this key is used in a context where an AES key is needed
        SecretKeySpec secretKeySpec = new SecretKeySpec(digested, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedOutputMessage = cipher.doFinal(outputMessage.getBytes());

        return encryptedOutputMessage;
    }

    public static void main(String args[]){
            Client alice = new Client();
            alice.receivePublicKey();
            alice.encryptSecretKeyRSA();
            alice.sendSecretKey();
            alice.establishConnection();
    }
}