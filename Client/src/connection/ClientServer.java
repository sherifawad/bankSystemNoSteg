package connection;

import Util.Uty;
import algorithm.ecc.ECPoint;
import algorithm.encryption.AESencryption;
import parameters.Client;
import parameters.PrivateKey;
import parameters.PublicKey;
import parameters.publicParameters;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import static sample.Controller.connectionCheck;


import static Util.Uty.*;

public class ClientServer extends Thread{
    private Client client;
    private publicParameters publicParameter;
    private  int serverPort;
    private  String serverName;
    private BigInteger n, d_C;
    private ECPoint P_C1;
    private Socket clientSocket;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;

    public ClientServer(String serverName, int serverPort) {
        this.serverName = serverName;
        this.serverPort = serverPort;
    }

    public ClientServer() {

    }

    public void run() {
//        char[] pwd = "a2".toCharArray();
        client = new Client("45", "zezo", "a2".toCharArray(), "51");

//        char[] pwd = "q2".toCharArray();
//        client = new Client("1236547896541596", "Sherif", pwd, "+201280412208");

        try {
            this.clientSocket = new Socket(serverName, serverPort);
            this.objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            this.objectInputStream = new ObjectInputStream(clientSocket.getInputStream());
            connectionCheck = true;
            process();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void process() {
        if (publicParameter == null) {
            send("Public", null);
        }
        startMessageReader();
//        readMessageLoop();
    }

    private void clintKeyGeneration() throws IOException {
        do {
            try {
//                do {
//                    d_C = Uty.randomBig(publicParameter.getOrder());
//                } while (d_C == null);
//                System.out.println("d_C " + d_C);

                d_C = new BigInteger("865049205761779596314415597297818988832033078586");
                P_C1 = publicParameter.getCurve().multiply(publicParameter.getBasePoint(), d_C);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        } while (P_C1.isPointOfInfinity() || publicParameter.getBasePoint() == P_C1
                || P_C1 == new ECPoint(0, 0));
        handleAuthentication(P_C1);
    }

    public ECPoint getPartialPublicKey() {
        return P_C1;
    }

    public BigInteger getPrivate() {
        return d_C;
    }


    private void send(String Command, Object messageBody){
        Message message;
        if (client.getPublicKey() != null) {
            message = new Message(Command, client.getClientID(), client.getPublicKey(), messageBody);
        } else if (this.getPartialPublicKey() != null){
            message = new Message(Command, client.getClientID(), null, messageBody);
        } else {
            message = new Message(Command, client.getClientID(), null, messageBody);
        }
        System.out.println("send Message " + message.toString());
        try {
            objectOutputStream.writeObject(message);
            objectOutputStream.flush();
            System.out.println("Message has been send");
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }


    private void startMessageReader() {
        Thread t = new Thread("MessageReader") {
            @Override
            public void run() {
                readMessageLoop();
            }
        };
        t.start();
    }

    private void readMessageLoop() {
        System.out.println(client.getAccountNumber());
        Message message;
        try {
            while ((message = Message.class.cast(objectInputStream.readObject())) != null){
                try {
                    String cmd = message.getCommand();
                    if ("public".equalsIgnoreCase(cmd)) {
                        System.out.println(" public command received");
                        handlePublicParameters(message);
                    } else if ("key".equalsIgnoreCase(cmd)) {
                        System.out.println("key command received");
                        handleKeyGeneration(message);
                    }  else if ("Error".equalsIgnoreCase(cmd)) {
                        handleErrorMessages(message);
                    } else {
                        System.out.println("CommandError");
                        send("Error", "CommandError");
                    }
                } catch (IOException e) {
                    send("Error", "FormatError");
                }
            }
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    private void handleErrorMessages(Message message) {
        System.out.println("-------------------");
        System.out.println("ID " + message.getClientID());
        System.out.println("PublicKey " + message.getPublicKey());
        System.out.println("MessageBody " + message.getMessageBody());
        System.out.println("-------------------");
    }

    private void handleKeyGeneration(Message message) throws IOException {
        if ("KGCServer".equals(message.getClientID())) {
            generationProcess((byte[]) message.getMessageBody());
        }
    }

    private void generationProcess(byte[] receivedMap) throws IOException {
        try {

            byte[] receivedHashMap = AESencryption.gcmMode(
                    Cipher.DECRYPT_MODE, client.getClientID().getBytes(),
                    client.getPassword(),
                    receivedMap);

//            byte[] receivedHashMap = AESencryption.gcmMode(Cipher.DECRYPT_MODE,
//                    "51".getBytes(),
//                    "a2".toCharArray(),
//                    receivedMap);
            
            HashMap<String, Object> hashMap = Uty.byteToMap(receivedHashMap);

            String receivedTimeStamp = (String) hashMap.get("t");
            if (currentDate().compareTo(receivedTimeStamp)<0){
                System.out.println("Wrong time stamp " + receivedTimeStamp);
                return;
            }


                BigInteger d_c2 = (BigInteger) hashMap.get("PartialKey");
                ECPoint R_C = (ECPoint) hashMap.get("PublicKey_YCoordinate");
                byte[] enConcatenateClient = Uty.byteConcatenate(Arrays.asList(
                        client.getClientID().getBytes(),
                        publicParameter.getKgcPublic().toString().getBytes(),
                        R_C.toString().getBytes(),
                        this.getPartialPublicKey().toString().getBytes()));

                BigInteger enHashClient = bytesHash(enConcatenateClient);
                ECPoint v1 = publicParameter.getCurve()
                        .add(R_C, publicParameter.getCurve()
                                .multiply(publicParameter.getKgcPublic(), enHashClient));

                ECPoint v2 = publicParameter.getCurve()
                        .multiply(publicParameter.getBasePoint(), d_c2);

                if (v1.toString().compareTo(v2.toString()) == 0) {
                    PrivateKey fullPrivateKey = new PrivateKey(this.getPrivate(), d_c2);
                    client.setPrivateKey(fullPrivateKey);
                    PublicKey fullPublicKey = new PublicKey(this.getPartialPublicKey(), R_C);
                    client.setPublicKey(fullPublicKey);

                    pointOfClientPartialKey(d_c2);

                } else {
                    System.out.println("Wrong Key");
                    send("Error", "WrongKey");
                }

        } catch (Exception e) {
            System.out.println(e.getMessage());
            send("Error", "DecryptionFailed");
        }
    }


    private void handleAuthentication(ECPoint PC1){

       if(PC1 == null || client.getName() == null)
           return;

        HashMap<String, Object> AccountHshMap = new HashMap<>();
        AccountHshMap.put("pc1", PC1);
        AccountHshMap.put("t", currentDate());
        AccountHshMap.put("name",
                (client.getName().hashCode()));
        System.out.println("hash code " + client.getName().hashCode());

            byte[] Encryption = (AESencryption.gcmMode
                    (Cipher.ENCRYPT_MODE, client.getClientID().getBytes(),
                            client.getPassword(),
                            mapTOBytes(AccountHshMap)));

//        byte[] Encryption = (AESencryption.gcmMode(Cipher.ENCRYPT_MODE,
//                "51".getBytes(),
//                "a2".toCharArray(),
//                mapTOBytes(AccountHshMap)));


        send("auth", Encryption);
    }

    private void handlePublicParameters(Message message) {
        if ("KGCServer".equalsIgnoreCase(message.getClientID())) {
            try {
                publicParameter = new publicParameters();
                publicParameter = publicParameter.getClass().cast(message.getMessageBody());
                if(publicParameter == null)
                    return;
                pointOfBankPartialKey(publicParameter);
                clintKeyGeneration();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void pointOfBankPartialKey(parameters.publicParameters Parameters) {
//        publicParameter = new publicParameters();
        byte[] h_c_data = Uty.byteConcatenate(Arrays.asList(publicParameter.getBankID().getBytes(),
                publicParameter.getKgcPublic().toString().getBytes(),
                publicParameter.getBankPublicKey().getYCoordinate().toString().getBytes(),
                publicParameter.getBankPublicKey().getXCoordinates().toString().getBytes()));
        BigInteger h_c = bytesHash(h_c_data);

        ECPoint p_b2 = publicParameter.getCurve()
                .add(publicParameter.getBankPublicKey().getYCoordinate(),
                publicParameter.getCurve()
                        .multiply(publicParameter.getKgcPublic(), h_c));

        client.setPointOfBankPartialKey(p_b2);
    }

    private void pointOfClientPartialKey(BigInteger partialPrivateKey) {
        ECPoint p_c2 = publicParameter.getCurve()
                .multiply(publicParameter.getBasePoint(), partialPrivateKey);
        client.setPointOfClientPartialKey(p_c2);
    }

    public publicParameters getPublicParameter() {
        return publicParameter;
    }

    public Client getClientParameter() {
        return client;
    }

    private boolean parametersCeckEquality(publicParameters a, publicParameters b) {


        if (a == null || b == null ) {
            return false;
        } else if (a.getBankAddress().equals(b.getBankAddress()) && a.getBankID().equals(b.getBankID()) &&
                a.getBankPort() == b.getBankPort() && a.getBankPublicKey().equals(b.getBankPublicKey()) &&
                a.getBasePoint().equals(b.getBasePoint()) && a.getCurve().equals(b.getCurve()) &&
                a.getKgcPublic().equals(b.getKgcPublic()) && a.getOrder().equals(b.getOrder())) {
            return true;
        }else {
            return false;
        }
    }
}
