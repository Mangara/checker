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
package checker;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Path;

public class Checker {

    private final Iterable<Path> readDirectories;
    private final Iterable<Path> writeDirectories;
    private PrintStream out = null; // System.out
    private PrintStream err = null; // System.err
    private final int timePerTest;
    private int mark;
    private int maxMark;
    private boolean securityBreached = false;
    private final StringBuilder output;

    public Checker(Iterable<Path> readDirectories, Iterable<Path> writeDirectories, int timePerTest) {
        this.readDirectories = readDirectories;
        this.writeDirectories = writeDirectories;
        this.timePerTest = timePerTest;
        output = new StringBuilder();
    }

    public void initialize() {
        setupSystem();

        mark = 0;
        maxMark = 0;
    }

    public void runTest(Test test) {
        runTest(test, timePerTest);
    }

    public void runTest(Test test, int timeForThisTest) {
        clearOutput();

        out.println("Testing " + test.getName() + ".");
        err.println("Testing " + test.getName() + ".");

        TestResult result = test.run(timeForThisTest, this);

        mark += result.score;
        maxMark += result.maxScore;

        if (result.comment != null && !result.comment.isEmpty()) {
            out.println(result.comment);
            err.println(result.comment);
        }

        if (result.details != null && !result.details.isEmpty()) {
            err.println(result.details);
        }

        if (securityBreached) {
            mark = 0;
            maxMark = 0;

            out.printf("Illegal action detected. Tests terminated.%n");
            err.printf("Illegal action detected. Tests terminated.%n");

            finish();
        }

        out.printf("Finished %s. Result: %d/%d.%n%n", test.getName(), result.score, result.maxScore);
        err.printf("Finished %s. Result: %d/%d.%n%n", test.getName(), result.score, result.maxScore);
    }

    public void finish() {
        out.printf("Tests complete. Total mark: %d/%d.%n", mark, maxMark);
        err.printf("Tests complete. Total mark: %d/%d.%n", mark, maxMark);

        System.exit(0);
    }

    public String getOutput() {
        return output.toString();
    }

    public void clearOutput() {
        output.delete(0, output.length());
    }

    private void setupSystem() {
        out = System.out;
        err = System.err;

        // Catch System.out to parse student output
        PrintStream studentOutput = new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                output.append(new String(new byte[]{(byte) b}));
            }

            @Override
            public void write(byte[] b) throws IOException {
                output.append(new String(b));
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                output.append(new String(b, off, len));
            }
        });

        System.setOut(studentOutput);

        // Change System.err to write to a limited System.err
        PrintStream limitedStdErr = new PrintStream(new OutputStream() {
            private int limit = 2000; // The maximum number of characters of debug output that are printed
            private int count = 0;
            private boolean warned = false;

            @Override
            public void write(int b) throws IOException {
                if (count < limit) {
                    err.write(b);
                    count++;
                } else if (!warned) {
                    err.println();
                    err.println("User program debug output truncated after the first " + limit + " bytes.");
                    warned = true;
                }
            }
        });

        System.setErr(limitedStdErr);
    }

    /**
     * Informs the checker that a security breach has taken place.
     * @param message
     */
    public void securityBreach(String message) {
        err.println("Security error: " + message);
        securityBreached = true;
    }

    public PrintStream getErr() {
        return err;
    }

    public PrintStream getOut() {
        return out;
    }

    public Iterable<Path> getReadDirectories() {
        return readDirectories;
    }

    public Iterable<Path> getWriteDirectories() {
        return writeDirectories;
    }
}
