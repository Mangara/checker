/*
 * Copyright 2014 Sander Verdonschot <sander.verdonschot at gmail.com>.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package checker.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class FileContentsChecker {

    /**
     * Checks whether the given files are equal.
     *
     * @param outputFile
     * @param solutionFile
     * @return true if the two files have identical contents, false otherwise.
     * @throws IOException
     */
    public static boolean checkEquality(File outputFile, File solutionFile) throws IOException {
        String line1, line2;

        try (BufferedReader in1 = new BufferedReader(new FileReader(outputFile));
                BufferedReader in2 = new BufferedReader(new FileReader(solutionFile))) {
            line1 = in1.readLine();
            line2 = in2.readLine();

            while (line1 != null && line1.equals(line2)) {
                line1 = in1.readLine();
                line2 = in2.readLine();
            }
        }

        if (line1 == null) {
            return line2 == null;
        } else {
            return false;
        }
    }

    /**
     * Returns a verbose explanation why the two given files are not equal. This
     * implementation is very costly, as it reads the entire file into memory.
     * Make sure to use it only on smaller files.
     *
     * @param output
     * @param solution
     * @return
     * @throws IOException
     */
    public static String detectEqualityProblem(File output, File solution) throws IOException {
        if (!output.exists()) {
            return "No output file was produced.";
        }

        if (!solution.exists()) {
            return "The solution file could not be found.";
        }

        try {
            BufferedReader rOutput = new BufferedReader(new FileReader(output));
            BufferedReader rSolution = new BufferedReader(new FileReader(solution));
            rOutput.close();
            rSolution.close();
        } catch (IOException e) {
            return "An exception occurred while trying to read the files: " + e.toString();
        }

        List<String> outputList = readFile(output);
        List<String> solutionList = readFile(solution);

        if (outputList.size() < solutionList.size()) {
            return "The output contains too few lines.";
        } else if (outputList.size() > solutionList.size()) {
            return "The output contains too many lines.";
        }

        Set<String> solutionLines = new HashSet<>(solutionList);
        Set<String> outputLines = new HashSet<>(outputList);

        for (String line : outputList) {
            if (!solutionLines.contains(line)) {
                return String.format("The output contains the following line, which is not in the solution:%n%s", line);
            }
        }

        for (String line : solutionList) {
            if (!outputLines.contains(line)) {
                return String.format("The output does not contain the following line from the solution:%n%s", line);
            }
        }

        if (outputList.equals(solutionList)) {
            System.err.println("!!!! detectProblem called on identical inputs !!!!");
            return "";
        } else {
            return "The order of lines in the output is not the same as in the solution.";
        }
    }

    /**
     * Returns true if any line in the file contains any of the given strings.
     *
     * @param file
     * @param strings
     * @return
     * @throws java.io.IOException
     */
    public static String fileContainsAny(File file, String... strings) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            int i = 1;
            String line = in.readLine();
            
            while (line != null) {
                for (String s : strings) {
                    if (line.contains(s)) {
                        in.close();
                        return String.format("Line %d: %s", i, line);
                    }
                }

                line = in.readLine();
                i++;
            }
        }
        
        return null;
    }

    private static List<String> readFile(File file) throws IOException {
        try (BufferedReader in = new BufferedReader(new FileReader(file))) {
            return in.lines().collect(Collectors.toList());
        }
    }
}
