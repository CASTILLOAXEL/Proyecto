import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CodeAnalyzerGUI implements ActionListener {
    private JTextArea codeInputArea;
    private JTextArea resultOutputArea;
    private Map<String, Set<String>> reservedWords;

    public CodeAnalyzerGUI() {
        JFrame frame = new JFrame("IDECODEC - Identificador de Lenguajes de Programación");
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setLayout(new BorderLayout());

        codeInputArea = new JTextArea(20, 30);
        resultOutputArea = new JTextArea(20, 30);
        resultOutputArea.setEditable(false);

        JButton analyzeButton = new JButton("Analizar Código");
        analyzeButton.addActionListener(this);

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(new JLabel("Ingrese el código:"), BorderLayout.NORTH);
        inputPanel.add(new JScrollPane(codeInputArea), BorderLayout.CENTER);
        inputPanel.add(analyzeButton, BorderLayout.SOUTH);

        JPanel outputPanel = new JPanel(new BorderLayout());
        outputPanel.add(new JLabel("Resultado del análisis:"), BorderLayout.NORTH);
        outputPanel.add(new JScrollPane(resultOutputArea), BorderLayout.CENTER);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, inputPanel, outputPanel);
        splitPane.setDividerLocation(400);

        frame.add(splitPane);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);

        reservedWords = new HashMap<>();
        initializeReservedWords();
    }

    private void initializeReservedWords() {
        reservedWords.put("PL/SQL", Set.of("CREATE", "TABLE"));
        reservedWords.put("T-SQL", Set.of("SELECT", "INSERT", "UPDATE", "DELETE"));
        reservedWords.put("C++", Set.of("include", "cout", "cin"));
        reservedWords.put("Pascal", Set.of("program", "begin", "end"));
        reservedWords.put("JavaScript", Set.of("function", "debugger", "extends"));
        reservedWords.put("HTML", Set.of("html", "body", "script"));
        reservedWords.put("Python", Set.of("def", "return", "import"));
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String code = codeInputArea.getText();
        String language = identifyLanguage(code);

        StringBuilder result = new StringBuilder();
        if (language != null) {
            result.append("Lenguaje identificado: ").append(language).append("\n");
            result.append("Realizando análisis...\n");

            List<String> lexicalErrors = performLexicalAnalysis(code, language);
            String syntaxErrors = performSyntaxAnalysis(code, language);
            String semanticErrors = performSemanticAnalysis(code, language);

            if (lexicalErrors.isEmpty() && syntaxErrors.isEmpty() && semanticErrors.isEmpty()) {
                result.append("Código válido.\n");
            } else {
                if (!lexicalErrors.isEmpty()) {
                    result.append("Errores léxicos:\n");
                    lexicalErrors.forEach(error -> result.append(error).append("\n"));
                }
                if (syntaxErrors != null) {
                    result.append("Errores sintácticos:\n").append(syntaxErrors).append("\n");
                }
                if (semanticErrors != null) {
                    result.append("Errores semánticos:\n").append(semanticErrors).append("\n");
                }
            }
        } else {
            result.append("No se pudo identificar el lenguaje del código.\n");
        }

        resultOutputArea.setText(result.toString());
    }

    private String identifyLanguage(String code) {
        if (Pattern.compile("\\bCREATE\\s+TABLE\\b").matcher(code).find()) {
            return "PL/SQL";
        } else if (Pattern.compile("\\b(SELECT|INSERT|UPDATE|DELETE)\\b").matcher(code).find()) {
            return "T-SQL";
        } else if (Pattern.compile("#include|\\b(cout|cin)\\b").matcher(code).find()) {
            return "C++";
        } else if (Pattern.compile("\\b(program|begin|end)\\b").matcher(code).find()) {
            return "Pascal";
        } else if (Pattern.compile("\\b(function|debugger|extends)\\b").matcher(code).find()) {
            return "JavaScript";
        } else if (Pattern.compile("<(html|body|script)>").matcher(code).find()) {
            return "HTML";
        } else if (Pattern.compile("\\b(def|return|import)\\b").matcher(code).find()) {
            return "Python";
        }
        return null;
    }

    private List<String> performLexicalAnalysis(String code, String language) {
        List<String> errors = new ArrayList<>();
        Set<String> keywords = reservedWords.get(language);
        if (keywords != null) {
            String[] tokens = code.split("\\s+");
            for (String token : tokens) {
                if (!keywords.contains(token) && !isValidIdentifier(token)) {
                    errors.add("Token inválido: " + token);
                }
            }
        }
        return errors;
    }

    private boolean isValidIdentifier(String token) {
        return token.matches("[a-zA-Z_][a-zA-Z0-9_]*");
    }

    private String performSyntaxAnalysis(String code, String language) {
        // Implementación del análisis sintáctico (simplificado)
        return null; // No se encontraron errores sintácticos
    }

    private String performSemanticAnalysis(String code, String language) {
        // Implementación del análisis semántico (simplificado)
        return null; // No se encontraron errores semánticos
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(CodeAnalyzerGUI::new);
    }
}




//////////




            @Override
    public void actionPerformed(ActionEvent e) {
        String code = codeInput.getText();
        String result = analyzeCode(code);
@@ -76,6 +112,8 @@ private String analyzeCode(String code) {
        String syntaxErrors = performSyntaxAnalysis(code, language);
        String semanticErrors = performSemanticAnalysis(code, language);

        result.append("Tabla de símbolos: ").append(symbolTable).append("\n");

        if (lexicalErrors.isEmpty() && syntaxErrors.isEmpty() && semanticErrors.isEmpty()) {
            result.append("Código válido.\nSimulación: ").append(simulateExecution(code, language));
        } else {
@@ -85,26 +123,6 @@ private String analyzeCode(String code) {
        return result.toString();
    }

   import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CodeAnalyzer implements ActionListener {

    private JTextArea codeInput;
    private JTextArea resultOutput;

    private Map<String, Set<String>> reservedWords = new HashMap<>();
    private Map<String, String> symbolTable = new HashMap<>();

    public CodeAnalyzer() {
        // Inicializar interfaz gráfica
        JFrame frame = new JFrame("Analizador de Código");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(600, 400);

        codeInput = new JTextArea();
        resultOutput = new JTextArea();

        JButton analyzeButton = new JButton("Analizar Código");
        analyzeButton.addActionListener(this);

        frame.add(new JScrollPane(codeInput), "Center");
        frame.add(analyzeButton, "South");
        frame.add(new JScrollPane(resultOutput), "East");

        frame.setVisible(true);

        initializeReservedWords();
    }

    private void initializeReservedWords() {
        reservedWords.put("PL/SQL", new HashSet<>(Arrays.asList("CREATE", "TABLE", "SELECT", "INSERT", "UPDATE", "DELETE")));
        reservedWords.put("T-SQL", new HashSet<>(Arrays.asList("CREATE", "TABLE", "SELECT", "INSERT", "UPDATE", "DELETE")));
        reservedWords.put("C++", new HashSet<>(Arrays.asList("include", "int", "float", "double", "bool", "char", "class", "public", "private", "protected")));
        reservedWords.put("Pascal", new HashSet<>(Arrays.asList("program", "begin", "end", "var")));
        reservedWords.put("JavaScript", new HashSet<>(Arrays.asList("function", "var", "let", "const", "debugger", "extends")));
        reservedWords.put("HTML", new HashSet<>(Arrays.asList("html", "body", "script")));
        reservedWords.put("Python", new HashSet<>(Arrays.asList("def", "return", "import")));
    }

    @Override
    public void actionPerformed(ActionEvent e) {
        String code = codeInput.getText();
        String result = analyzeCode(code);
        resultOutput.setText(result);
    }

    private String analyzeCode(String code) {
        StringBuilder result = new StringBuilder();

        String language = identifyLanguage(code);
        if (language == null) {
            return "No se pudo identificar el lenguaje de programación.";
        }

        result.append("Lenguaje identificado: ").append(language).append("\n");

        String lexicalErrors = performLexicalAnalysis(code, language);
        String syntaxErrors = performSyntaxAnalysis(code, language);
        String semanticErrors = performSemanticAnalysis(code, language);

        result.append("Errores léxicos: ").append(lexicalErrors).append("\n");
        result.append("Errores sintácticos: ").append(syntaxErrors).append("\n");
        result.append("Errores semánticos: ").append(semanticErrors).append("\n");

        if (lexicalErrors.isEmpty() && syntaxErrors.isEmpty() && semanticErrors.isEmpty()) {
            result.append("Código válido.\nSimulación: ").append(simulateExecution(code, language));
        }

        return result.toString();
    }

    private String identifyLanguage(String code) {
        if (code.matches(".*\\bCREATE\\s+TABLE\\b.*")) {
            return "PL/SQL";
        } else if (code.matches(".*\\bSELECT\\b.*") || code.matches(".*\\bINSERT\\b.*") || code.matches(".*\\bUPDATE\\b.*") || code.matches(".*\\bDELETE\\b.*")) {
            return "T-SQL";
        } else if (code.matches(".*#include.*") || code.matches(".*\\bcout\\b.*") || code.matches(".*\\bcin\\b.*")) {
            return "C++";
        } else if (code.matches(".*\\bprogram\\b.*") || code.matches(".*\\bbegin\\b.*") || code.matches(".*\\bend\\b.*")) {
            return "Pascal";
        } else if (code.matches(".*\\bfunction\\b.*") || code.matches(".*\\bdebugger\\b.*") || code.matches(".*\\bextends\\b.*")) {
            return "JavaScript";
        } else if (code.matches(".*<html>.*") || code.matches(".*<body>.*") || code.matches(".*<script>.*")) {
            return "HTML";
        } else if (code.matches(".*\\bdef\\b.*") || code.matches(".*\\breturn\\b.*") || code.matches(".*\\bimport\\b.*")) {
            return "Python";
        }
        return null;
    }

    private String performLexicalAnalysis(String code, String language) {
        if (!"C++".equals(language)) {
            return "Este analizador solo admite C++.";
        }

        Pattern pattern = Pattern.compile(
            "\\b(int|char|void|double|float|bool|if|else|for|while|return|include|using|namespace|class|public|private|protected)\\b|" +
            "\\b\\d+\\b|" +
            "[+\\-*/=]|" +
            "\\b[_a-zA-Z][_a-zA-Z0-9]*\\b"
        );

        Matcher matcher = pattern.matcher(code);
        List<String> tokens = new ArrayList<>();
        List<String> invalidTokens = new ArrayList<>();

        while (matcher.find()) {
            String token = matcher.group();
            tokens.add(token);
            if (token.matches("\\b[a-zA-Z][_a-zA-Z0-9]*\\b") && !token.matches("[A-Za-z][A-Za-z0-9_]*")) {
                invalidTokens.add(token);
            }
        }

        String response = "Tokens encontrados: " + String.join(", ", tokens);
        if (!invalidTokens.isEmpty()) {
            response += "\nIdentificadores inválidos encontrados: " + String.join(", ", invalidTokens);
        }
        return response;
    }

    private String performSyntaxAnalysis(String code, String language) {
        switch (language) {
            case "PL/SQL":
                if (!code.matches("CREATE TABLE [a-zA-Z_][a-zA-Z0-9_]* \\(.*\\);")) {
                    return "Error sintáctico: La sintaxis de la instrucción SQL es incorrecta.\n";
                }
                break;
            case "C++":
                return performCPPSyntaxAnalysis(code);
            case "Pascal":
                return "El lenguaje " + language + " no tiene un análisis sintáctico implementado.";
            default:
                return "El lenguaje " + language + " no está soportado.";
        }
        return "";
    }

    private String performCPPSyntaxAnalysis(String code) {
        StringBuilder syntaxErrors = new StringBuilder();

        int ifCount = countOccurrences(code, "\\bif\\b");
        int elseCount = countOccurrences(code, "\\belse\\b");
        if (ifCount != elseCount) {
            syntaxErrors.append("Error: La cantidad de bloques 'if' y 'else' no coincide.\n");
        }

        int forCount = countOccurrences(code, "\\bfor\\b");
        int leftBraceCount = countOccurrences(code, "\\{");
        if (forCount > 0 && forCount != leftBraceCount) {
            syntaxErrors.append("Error: La cantidad de bloques 'for' no coincide con la cantidad de llaves '{'.\n");
        }

        int whileCount = countOccurrences(code, "\\bwhile\\b");
        if (whileCount > 0 && whileCount != leftBraceCount) {
            syntaxErrors.append("Error: La cantidad de bloques 'while' no coincide con la cantidad de llaves '{'.\n");
        }

        int doCount = countOccurrences(code, "\\bdo\\b");
        int rightBraceCount = countOccurrences(code, "\\}");
        if (doCount > 0 && doCount != rightBraceCount) {
            syntaxErrors.append("Error: La cantidad de bloques 'do' no coincide con la cantidad de llaves '}'.\n");
        }

        Pattern functionPattern = Pattern.compile("\\b\\w+\\s+\\w+\\s*\\(.?\\)\\s\\{");
        Matcher functionMatcher = functionPattern.matcher(code);
        while (functionMatcher.find()) {
            String functionDeclaration = functionMatcher.group();
            if (!functionDeclaration.contains("return") && !functionDeclaration.contains("void")) {
                syntaxErrors.append("Error: La función '").append(functionDeclaration).append("' no tiene un retorno.\n");
            }
        }

        return syntaxErrors.toString();
    }

    private int countOccurrences(String input, String regex) {
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        int count = 0;
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    private String performSemanticAnalysis(String code, String language) {
        if (language.equals("PL/SQL") && code.contains("CREATE TABLE") && !code.contains(";")) {
            return "Error semántico: Falta el punto y coma al final de la instrucción SQL.\n";
        }

        StringBuilder semanticErrors = new StringBuilder();

        Pattern assignmentPattern = Pattern.compile("\\b(int|char|double|float|bool|string)\\s+\\w+\\s*=\\s*[^;]+;");
        Matcher matcher = assignmentPattern.matcher(code);
        while (matcher.find()) {
            String assignment = matcher.group();
            String[] parts = assignment.split("=");
            String varType = parts[0].trim().split("\\s+")[0];
            String value = parts[1].trim().replace(";", "");
            if (!isValueValidForType(varType, value)) {
                semanticErrors.append("Error semántico: La variable '").append(parts[0].trim().split("\\s+")[1]).append("' no puede ser asignada al valor '").append(value).append("'.\n");
            }
        }

        return semanticErrors.toString();
    }

    private boolean isValueValidForType(String varType, String value) {
        try {
            switch (varType) {
                case "int":
                    Integer.parseInt(value);
                    break;
                case "double":
                case "float":
                    Double.parseDouble(value);
                    break;
                case "bool":
                    if (!value.equalsIgnoreCase("true") && !value.equalsIgnoreCase("false")) {
                        return false;
                    }
                    break;
                case "char":
                    if (value.length() != 1) {
                        return false;
                    }
                    break;
                default:
                    return true;
            }
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    private String simulateExecution(String code, String language) {
        if (!"C++".equals(language)) {
            return "Simulación no disponible para " + language + ".";
        }

        Pattern outputPattern = Pattern.compile("cout\\s*<<\\s*([^;]+);");
        Matcher matcher = outputPattern.matcher(code);
        StringBuilder simulationResult = new StringBuilder();
        while (matcher.find()) {
            simulationResult.append(matcher.group(1).replace("<<", "").trim());
        }
        return simulationResult.toString();
    }

    public static void main(String[] args) {
        new CodeAnalyzer();
    }
}
