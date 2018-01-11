package de.neumann.quickencrypt;
/**
 * Created by GN on 01.01.2017.
 */

import java.io.File;
import java.util.*;

public class QuickEncrypter {

    private static final String welcomeText = "For a list of arguments use '?' as a parameter";

    private static final String helpText =
            "[PROG] [OPT] [FILEPATH]\n"
            + "\t[OPT]\n"
            + "\t-aes192 for AES-192 encryption\n"
            + "\t-aes256 for AES-256 encryption\n"
            + "\t-pw put password for decrypt or encrypt after this tag\n"
            + "\t-dec use this for decrypting";

    public static void main(String... args) {

        EncryptionTool.AESMode mode = EncryptionTool.AESMode.AES_128;
        boolean decrypt = false;

        String filePath = null;

        Scanner inputs = new Scanner(System.in);

        String pw = null;

        System.out.println(welcomeText);

        for (int i = 0; i < args.length; i++) {

            switch (args[i]) {

                case "?":
                case "-help":
                    System.out.println(helpText);
                    return ;
                case "-aes256" :
                    mode = EncryptionTool.AESMode.AES_256;
                    break;
                case "-aes192" :
                    mode = EncryptionTool.AESMode.AES_192;
                    break;
                case "-pw":
                    pw = args[i + 1];
                    i++;
                    break;
                case "-dec":
                    decrypt = true;
                    break;
                default:
                    filePath = args[i];
                    break;
            }

        }

        if (pw == null) {
            System.out.println("Please enter a password");
            pw = inputs.nextLine();
        }

        if (filePath == null) {
            System.out.println("Please enter a path");
            filePath = inputs.nextLine();
        }

        File f = new File(filePath);

        if (!f.exists()) {
            System.out.println("File does not not exist");
            return;
        }

        EncryptionTool et = new EncryptionTool(mode, pw);

        List<File> files = new ArrayList<>();

        if (f.isFile()) {
            files.add(f);
        } else {
            getFiles(f, files);
        }

        for (File file : files) {
            if (decrypt) {
            	System.out.printf("Decrypting file %s...\n", file .getName());
                et.decrypt(file);
            } else {
				System.out.printf("Encrypting file %s...\n", file .getName());
                et.encrypt(file);
            }
        }
    }

    private static void getFiles(File folder, List<File> files) {
    	Queue<File> folders = new LinkedList<>();
    	folders.add(folder);

    	while (!folders.isEmpty()) {
    		files.addAll(Arrays.asList(folders.peek().listFiles(x -> x.isFile())));
    		folders.addAll(Arrays.asList(folders.poll().listFiles(x -> x.isDirectory())));
		}
	}
}
