import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class PasswordValidator implements Runnable {
    private String password;  // Contraseña a validar

    // Expresión regular para validar la contraseña
    private static final String PASSWORD_REGEX = "^(?=(.*[A-Z]){2})(?=(.*[a-z]){3})(?=(.*\\d)){1}(?=(.*[\\W_])){1}.{8,}$";

    // Constructor para inicializar la contraseña
    public PasswordValidator(String password) {
        this.password = password;
    }

    // Método que se ejecutará cuando el hilo sea lanzado
    @Override
    public void run() {
        // Verificar si la contraseña es válida
        if (isValidPassword(password)) {
            System.out.println("La contraseña '" + password + "' es válida.");
        } else {
            System.out.println("La contraseña '" + password + "' no es válida.");
        }
    }

    // Método que utiliza la expresión regular para validar la contraseña
    private boolean isValidPassword(String password) {
        Pattern pattern = Pattern.compile(PASSWORD_REGEX);
        Matcher matcher = pattern.matcher(password);
        return matcher.matches();  // Retorna true si la contraseña coincide con la expresión regular
    }

    // Método principal que crea los hilos y lanza la validación
    public static void main(String[] args) {
        // Lista de contraseñas para validar
        String[] passwords = {
                "Password123!",  // Contraseña válida
                "12345",         // Contraseña no válida
                "P@ssw0r",       // Contraseña no válida
                "AbcD1$2xyz",    // Contraseña válida
                "Short1!"        // Contraseña no válida
        };

        // Crear y lanzar hilos para validar las contraseñas
        for (String password : passwords) {
            PasswordValidator validator = new PasswordValidator(password);  // Crear el objeto de validación
            Thread thread = new Thread(validator);  // Crear un hilo para validar la contraseña
            thread.start();  // Lanzar el hilo para validar la contraseña
        }
    }
}