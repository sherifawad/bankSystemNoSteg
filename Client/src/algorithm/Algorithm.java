package algorithm;

import Util.Uty;

import algorithm.ecc.ECPoint;
import algorithm.encryption.AESencryption;
import connection.ClientServer;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.math.BigInteger;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

import static Util.Uty.*;
import static algorithm.encryption.EncUtil.readBytes;

//import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;

public class Algorithm {

    private final ClientServer bankClient;

    public Algorithm(ClientServer bankClient) {
        this.bankClient = bankClient;
    }

    public  HashMap<String, Object> signcryption(String[] srcFiles, Path tempDir)  {
//        System.out.println("publicParameters.getOrder() " + bankClient.getPublicParameter().getOrder());
        BigInteger r_c ;
//        do {
////            r_c = Uty.randomBig(bankClient.getPublicParameter().getOrder());
////        } while (r_c == null);
////        System.out.println("r_c " + r_c);

        r_c = new BigInteger("907537726282672001737046682329929935372443483351");

        ECPoint z_c = bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getBasePoint()
                , r_c);
        ECPoint K_1 = bankClient.getPublicParameter().getCurve().multiply
                (bankClient.getClientParameter().getPointOfBankPartialKey(), r_c);
        byte[] Key = K_1.x.toByteArray();
//        System.out.println(Arrays.toString(Key));
        System.out.println("K_1 " + K_1);



        HashMap<String, Object> AccountHshMap = new HashMap<>();
        AccountHshMap.put("IDC",  bankClient.getClientParameter().getClientID());
        AccountHshMap.put("t", currentDate());
        AccountHshMap.put("acc",  bankClient.getClientParameter().getAccountNumber());
        byte[] cipherAccount = Uty.xorWithKey(mapTOBytes(AccountHshMap), K_1.y.toByteArray());

        String pathFile = tempDir + "/Source.zip";
        Uty.zip(pathFile, srcFiles);


        byte[] cipherText = new byte[0];
        try {
            cipherText = Uty.xorWithKey(readBytes(new File(pathFile)), Key);

        } catch (Exception e) {
            e.printStackTrace();
        }



//        byte[] IDc = Uty.xorWithKey(bankClient.getClientParameter().getClientID().getBytes(), K_1.y.toByteArray());


        byte[] h_c_data = Uty.byteConcatenate(Arrays.asList(cipherAccount,
                cipherText,
                bankClient.getClientParameter().getClientID().getBytes(),
                z_c.toString().getBytes(),
                bankClient.getClientParameter().getPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getPublicParameter().getBankPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getPublicParameter().getKgcPublic().toString().getBytes()));
//                (bankClient.getPublicParameter().getKgcPublic().toString().getBytes())));
        System.out.println("cipherAccount " + Arrays.toString(cipherAccount));
        System.out.println("cipherText " + Arrays.toString(cipherText));
        System.out.println("z_c " + z_c);
        System.out.println("ClientID() " + bankClient.getClientParameter().getClientID());
        System.out.println("pc1 " + bankClient.getClientParameter().getPublicKey().getXCoordinates());
        System.out.println("pb1 " + bankClient.getPublicParameter().getBankPublicKey().getXCoordinates());
        System.out.println("pkgc " + bankClient.getPublicParameter().getKgcPublic());


        BigInteger h_c = Uty.bytesHash(h_c_data);
        System.out.printf("h_c " + h_c);

        BigInteger S = (r_c.subtract(h_c.multiply(bankClient.getClientParameter().getPrivateKey().getXCoordinates().add
                (bankClient.getClientParameter().getPrivateKey().getYCoordinate())))).mod
                (bankClient.getPublicParameter().getOrder());

//        System.out.println("S " + S);
        ECPoint R = bankClient.getPublicParameter().getCurve()
                .multiply(bankClient.getPublicParameter().getCurve()
                        .add(bankClient.getClientParameter().getPublicKey().getXCoordinates(),
                                bankClient.getClientParameter().getPointOfClientPartialKey()),
                        h_c);

        HashMap<String, Object>  hshMap = new HashMap<>();
        hshMap.put("S", S);
        hshMap.put("R", R);
        hshMap.put("c", cipherText);
        System.out.println("Cipher " + cipherText);
        hshMap.put("ACC", cipherAccount);

//        hshMap.put("IDcB", IDc);

//        byte[] IDcBc = Uty.xorWithKey(hshMap.get("IDcB"), K_1.y.toByteArray());
//        String receivedID = new String(IDcBc);
//        System.out.println("receivedID " + receivedID);

        return hshMap;
    }

    public byte[] unSigncryption(HashMap<String,Object> HashMap) throws IOException {

//        BigInteger r_x = new BigInteger(1, HashMap.get("r_x"));
////        System.out.println("r_x " + r_x);
//        BigInteger r_y = new BigInteger(1, HashMap.get("r_y"));
////        System.out.println("r_y " + r_y);
//        BigInteger Sr = new BigInteger(1, HashMap.get("s"));
////        System.out.println("S " + Sr);
////        System.out.println("Cipher " + HashMap.get("c"));
//        ECPoint Rr = new ECPoint(r_x, r_y);
////        System.out.println("Rr " + Rr);

        BigInteger Sr = (BigInteger) HashMap.get("S");
        ECPoint Rr = (ECPoint) HashMap.get("R");

        ECPoint z_sb = bankClient.getPublicParameter().getCurve().add
                (bankClient.getPublicParameter().getCurve().multiply(bankClient.getPublicParameter().getBasePoint(), Sr)
                        , Rr);
//        System.out.println("z_sb " + z_sb);

        ECPoint K_1b = bankClient.getPublicParameter().getCurve().multiply
                (z_sb, bankClient.getClientParameter().getPrivateKey().getYCoordinate());
//        System.out.println("K_1b " + K_1b);

        System.out.println("K_1b.y " + K_1b.y);

        byte[] cipherAccount = Uty.xorWithKey((byte[]) HashMap.get("ACC"), K_1b.y.toByteArray());

        HashMap<String, Object> AccountHshMap = byteToMap(cipherAccount);

        if (Uty.currentDate().compareTo((String) AccountHshMap.get("t")) < 0)
            return null;

        String receivedID = (String) AccountHshMap.get("IDb");

        System.out.println("receivedID " + receivedID);
//
        if (receivedID == null)
            return null;

        if (!(receivedID.equals(bankClient.getPublicParameter().getBankID())))
            return null;


        byte[] plainText = null;
        byte[] h_b_data = Uty.byteConcatenate(Arrays.asList((byte[]) HashMap.get("ACC"),
                (byte[]) HashMap.get("c"),
                bankClient.getPublicParameter().getBankID().getBytes(),
                z_sb.toString().getBytes(),
                bankClient.getClientParameter().getPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getPublicParameter().getBankPublicKey().getXCoordinates().toString().getBytes(),
                bankClient.getPublicParameter().getKgcPublic().toString().getBytes()));

        BigInteger h_b = Uty.bytesHash(h_b_data);


        ECPoint R_b = bankClient.getPublicParameter().getCurve()
                .multiply(bankClient.getPublicParameter().getCurve()
                                .add(bankClient.getPublicParameter().getBankPublicKey().getXCoordinates(),
                                        bankClient.getClientParameter().getPointOfBankPartialKey()),
                        h_b);


        if (R_b.toString().equals(Rr.toString())) {
            System.out.println("Is Equal");
            byte[] receivedKey = K_1b.x.toByteArray();
            plainText = Uty.xorWithKey((byte[]) HashMap.get("c"), receivedKey);
        }
        System.out.println("plainText is " + Arrays.toString(plainText));

        System.out.println("cipher is " + Arrays.toString((byte[]) HashMap.get("c")));
        System.out.println("z_b is " + z_sb);
        System.out.println("pc1 " + bankClient.getClientParameter().getPublicKey().getXCoordinates());
        System.out.println("pb1 " + bankClient.getPublicParameter().getBankPublicKey().getXCoordinates());
        System.out.println("pkgc " + bankClient.getPublicParameter().getKgcPublic());
        System.out.println("h_b is " + h_b);
        System.out.println("pb2 " + bankClient.getClientParameter().getPointOfBankPartialKey());
        System.out.println("R is " + R_b);
        System.out.println("S is " + Sr);

        return plainText;
    }

}
