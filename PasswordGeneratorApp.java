import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;
import java.util.Base64;

public class PasswordGeneratorApp extends JFrame {

    private JTextField passwordField;
    private JTextField encryptedPasswordField;
    private JTextField passwordLengthField;

    public PasswordGeneratorApp() {
        setTitle("Password Generator");
        setSize(400, 300);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(5, 2, 10, 10));

        JLabel lengthLabel = new JLabel("Password Length:");
        passwordLengthField = new JTextField();

        JLabel passwordLabel = new JLabel("Generated Password:");
        passwordField = new JTextField();
        passwordField.setEditable(false);

        JLabel encryptedPasswordLabel = new JLabel("Encrypted Password:");
        encryptedPasswordField = new JTextField();
        encryptedPasswordField.setEditable(false);

        JButton generateButton = new JButton("Generate");
        generateButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                generatePasswordAndEncrypt();
            }
        });

        panel.add(lengthLabel);
        panel.add(passwordLengthField);
        panel.add(passwordLabel);
        panel.add(passwordField);
        panel.add(encryptedPasswordLabel);
        panel.add(encryptedPasswordField);
        panel.add(generateButton);

        add(panel);

        setVisible(true);
    }

    private void generatePasswordAndEncrypt() {
        try {
            int length = Integer.parseInt(passwordLengthField.getText());
            String password = generatePassword(length);
            SecretKey secretKey = generateSecretKey();
            String encryptedPassword = encryptPassword(password, secretKey);

            passwordField.setText(password);
            encryptedPasswordField.setText(encryptedPassword);
        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(this, "Error: " + e.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // Method to generate a random password
    private String generatePassword(int length) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_+=";
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            password.append(characters.charAt(index));
        }

        return password.toString();
    }

    // Method to encrypt the password
    private String encryptPassword(String password, SecretKey secretKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    // Method to generate a secret key for AES encryption
    private SecretKey generateSecretKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for AES-256
        return keyGen.generateKey();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new PasswordGeneratorApp();
            }
        });
    }
}