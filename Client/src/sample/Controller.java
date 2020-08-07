package sample;

import Util.Uty;
import algorithm.Algorithm;;
import connection.ClientServer;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ListView;
import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import parameters.Client;
import parameters.publicParameters;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.ResourceBundle;


public class Controller  implements Initializable{

    @FXML
    private Button btnsm ;
    @FXML
    private Button btnso ;
    @FXML
    private Button  btnse;
    @FXML
    private Button btnsc ;
    @FXML
    private Button  btnrm;
    @FXML
    private Button btnro ;
    @FXML
    private Button  btnre;
    @FXML
    private Button  btnrc;
    @FXML
    private ListView listview;
    @FXML
    String fileAsString;
    @FXML
    String stegFileAsString;
    @FXML
    String outputFile;
    @FXML
    String outputDir;
    @FXML
    String[] srcFiles;
    @FXML
    ArrayList<String> filesAsString;
    @FXML
    File selectedFile;
    @FXML
    File stegFile;
    @FXML
    File saveFile;
    @FXML
    File selectedDirectory;
    @FXML
    List<File> selectedFiles;
    @FXML
    private ArrayList<Button> buttonArrayList;
    @FXML
    private Client client = new Client();
    @FXML
    private Algorithm algorithm;
    @FXML
    private publicParameters publicParameter;
    @FXML
    public static boolean connectionCheck = false;
    @FXML
    private HashMap<String, Object> newMap;


    @Override
    public void initialize(URL location, ResourceBundle resources) {
        buttonsList();
        Thread thread = new Thread();
        final Thread finalThread = thread;
        thread = new Thread("getClientPublicKey") {
            public void run() {
                disableButtons();

                ClientServer bankClient = null;
//                ClientServer bankClient = new ClientServer();

                do {

                    if (!connectionCheck) {
//                    bankClient = new ClientServer("192.168.1.135", 7894);
                        bankClient = new ClientServer("localhost", 7894);
                        bankClient.start();

                        try {
                            Thread.sleep(5000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }
                    } else {
                        bankClient.interrupt();
                    }
//                    if(bankClient.getClientParameter().getPointOfBankPartialKey() != null) {
                    if(Client.getPublicKey() != null) {
                        System.out.println("Connected");
                        algorithm = new Algorithm(bankClient);
                        publicParameter = bankClient.getPublicParameter();
                        System.out.printf("public psrs order " + publicParameter.getOrder());
                        enableButtons();
                        finalThread.interrupt();
                        break;
                    }


                } while (Client.getPublicKey() == null);


//                ClientServer bankClient = new ClientServer("localhost", 7894);
//                bankClient.start();
//                while(true) {
//
//                    if(Client.getPublicKey() != null) {
//                        break;
//                    }
//                }
//                publicParameter = bankClient.getPublicParameter();
//                client = bankClient.getClientParameter();
//                algorithm = new Algorithm(publicParameter, client);
//                enableButtons();
//                this.interrupt();
            }
        };
        thread.start();
    }


    public void singleChooser(){
        FileChooser fc = new FileChooser();

        fc.setInitialDirectory(new File("C:\\"));

        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Files",  "*.txt"));

        selectedFile = fc.showOpenDialog(null);
        if(selectedFile != null){
//            listview.getItems().add(selectedFile);
            fileAsString = selectedFile.toString();
        }
    }


    public void multiChooser() {
        FileChooser fc = new FileChooser();
//        fc.setInitialDirectory(new File(System.getProperty("D:\\")));
        fc.setInitialDirectory(new File("C:\\"));
//        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("PDF Files", "*.pdf"));
        selectedFiles = fc.showOpenMultipleDialog(null);
//        Object[] files = new Object[0];
        String files = null;
        filesAsString = new ArrayList<>();
        if (selectedFiles != null) {
            for(File s : selectedFiles)
                filesAsString.add(s.toString());
            srcFiles = filesAsString.toArray(new String[filesAsString.size()]);
//            listview.getItems().addAll(selectedFile);
//            files = selectedFile.toArray();

//            filesAsString = Arrays.toString(files).split(",");
        }
//        filesAsString = Arrays.copyOf(files, files.length, String[].class);
    }

    public void fileSaving(){
        FileChooser fc = new FileChooser();
//        fc.setInitialDirectory(new File(System.getProperty("D:\\")));
        fc.setInitialDirectory(new File("C:\\"));

        fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("TXT Files", "*.txt"));
//        else
//           fc.getExtensionFilters().add(new FileChooser.ExtensionFilter("Properities Files", "*.properties"));
        saveFile = fc.showSaveDialog(null);
        if (saveFile != null) {
            outputFile = saveFile.toString();
        }
        else outputFile = null;

    }

    public void outputDir(){
        DirectoryChooser dc = new DirectoryChooser();
//        chooser.setTitle("JavaFX Projects");
        File defaultDirectory = new File("C:\\");
        dc.setInitialDirectory(defaultDirectory);
        selectedDirectory = dc.showDialog(null);
        if (selectedDirectory != null) {
            outputDir = selectedDirectory.toString();
        }
        else outputDir = null;
    }



    public void senderExecute(){
        System.out.println("publicParameters.getOrder() " + publicParameter.getOrder());

        if (selectedFiles == null) {
            System.out.println("Please select secret message");
            return;
        }

        if (saveFile == null) {
            System.out.println("select output file");
            return;
        }
        new Thread() {
            public void run() {
                Platform.runLater(new Runnable() {
                    public void run() {
                        disableButtons();
                    }
                });
                SendProcess();
                Platform.runLater(new Runnable() {
                    public void run() {
                        enableButtons();
                    }
                });
            }
        }.start();

    }


    private void SendProcess() {
        Path tempDir = null;
        try {
            tempDir = Files.createTempDirectory("CSCrypto");
            HashMap<String, Object> hmap = algorithm.signcryption(srcFiles, tempDir);
            if (hmap == null)
                return;
            Uty.WriteMapToFile(hmap, outputFile);

        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            if (tempDir != null) {
                Uty.remove(tempDir);
            }
            srcFiles = null;
            outputFile = "";
        }

    }




    public void receiveExecute() {
        if (selectedFile == null) {
            System.out.println("please select a file");
        }
        if (selectedDirectory == null) {
            System.out.println("please select am output directory");
            return;
        }

        new Thread() {
            public void run() {
                Platform.runLater(new Runnable() {
                    public void run() {
                        disableButtons();
                    }
                });

                ReceiveProcess();

                Platform.runLater(new Runnable() {
                    public void run() {
                        enableButtons();

                    }
                });
            }
        }.start();

    }

    private void ReceiveProcess() {

        if (fileAsString == null)
            return;

            newMap = Uty.fileToMap(fileAsString);

            Path tempDir_received = null;
            String deOutput = null;
            try {
                tempDir_received = Files.createTempDirectory("CRCrypto");
                deOutput = tempDir_received + "/plain.zip";
            } catch (IOException e) {
                e.printStackTrace();
            }

            byte[] plainText = null;
            try {
                plainText = algorithm.unSigncryption(newMap);
            } catch (IOException e) {
                e.printStackTrace();
            }

            if (plainText != null) {
                Uty.writeByteToFile(tempDir_received + "/plain.zip", plainText);
                Uty.unZipIt(deOutput, outputDir);
            } else {
                System.out.println(" Empty Message");
            }

            Uty.remove(tempDir_received);

    }


    private void buttonsList() {
        buttonArrayList =new ArrayList<>();
        buttonArrayList.add(btnsm);
//        buttonArrayList.add(btnsi);
        buttonArrayList.add(btnso);
        buttonArrayList.add(btnse);
        buttonArrayList.add(btnsc);
        buttonArrayList.add(btnrm);
        buttonArrayList.add(btnro);
        buttonArrayList.add(btnre);
        buttonArrayList.add(btnrc);
    }

    private void disableButtons() {
        for (Button btn : buttonArrayList) {
            btn.setDisable(true);
        }
    }

    private void enableButtons() {
        for (Button btn : buttonArrayList) {
            btn.setDisable(false);
        }
    }

}

