package parameters;

import java.io.Serializable;

import algorithm.ecc.ECPoint;

public class Client implements Serializable {
    private static final long serialVersionUID = 5394275479895L;

    private String  accountNumber;
    private  String name;
    private  char[] password;
    private  ECPoint pointOfClientPartialKey;
    private  ECPoint pointOfBankPartialKey;
    private PrivateKey privateKey;
    private  String clientID;
    private static PublicKey publicKey;

    public Client() {
    }

    public String getName() {
        return name;
    }

    public char[] getPassword() {
        return password;
    }


    public String getClientID() {
        return clientID;
    }

    public static PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String  getAccountNumber() {
        return accountNumber;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public ECPoint getPointOfClientPartialKey() {
        return pointOfClientPartialKey;
    }

    public void setPointOfClientPartialKey(ECPoint pointOfClientPartialKey) {
        this.pointOfClientPartialKey = pointOfClientPartialKey;
    }

    public ECPoint getPointOfBankPartialKey() {
        return pointOfBankPartialKey;
    }

    public void setPointOfBankPartialKey(ECPoint pointOfBankPartialKey) {
        this.pointOfBankPartialKey = pointOfBankPartialKey;
    }

    public Client(ECPoint pointOfClientPartialKey, ECPoint pointOfBankPartialKey, PrivateKey privateKey, final String clientID, final PublicKey publicKey) {
        this.pointOfClientPartialKey = pointOfClientPartialKey;
        this.pointOfBankPartialKey = pointOfBankPartialKey;
        this.privateKey = privateKey;
        this.clientID = clientID;
        this.publicKey = publicKey;
    }

    public Client(final String  accountNumber, String name, char[] password , final String clientID) {
        this.accountNumber = accountNumber;
        this.name = name;
        this.password = password;
        this.clientID = clientID;
    }
}

