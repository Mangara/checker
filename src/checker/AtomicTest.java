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

import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;

public abstract class AtomicTest extends Test {

    private final int marks;
    
    public AtomicTest(String name, int marks) {
        super(name);
        this.marks = marks;
    }

    @Override
    @SuppressWarnings("deprecation")
    public TestResult run(int timePerTest, Checker checker) {
        RunnableTest test = new RunnableTest(checker);
        Thread testThread = new Thread(test, "TestThread");

        testThread.start();

        long start = System.currentTimeMillis();

        while (testThread.isAlive() && System.currentTimeMillis() - start < timePerTest) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
            }
        }

        if (testThread.isAlive()) {
            checker.getErr().printf("Time limit (%.0fs) exceeded for %s. Forcing shutdown...%n", timePerTest / 1000.0, getName());

            testThread.stop();
            try {
                testThread.join();
            } catch (InterruptedException ex) {
            }

            return fail(String.format("Time limit (%.0fs) exceeded for %s.", timePerTest / 1000.0, getName()));
        } else {
            checker.getErr().printf("Test for %s took %f seconds.%n", getName(), (System.currentTimeMillis() - start) / 1000.0);
        }

        return test.getResult();
    }

    public abstract TestResult test(Checker checker) throws Exception;

    public TestResult fail(String comment) {
        return fail(comment, null);
    }

    public TestResult fail(String comment, String details) {
        return new TestResult(0, marks, comment, details);
    }

    public int getMarks() {
        return marks;
    }

    class RunnableTest implements Runnable {

        private TestResult result = fail(String.format("Test for %s did not finish.", AtomicTest.this.getName()));
        private Checker checker;

        RunnableTest(Checker checker) {
            this.checker = checker;
        }

        public TestResult getResult() {
            return result;
        }

        @Override
        public void run() {
            try {
                result = test(checker);
            } catch (CorrectnessException e) {
                result = fail(String.format("Test for %s failed%s", AtomicTest.this.getName(), (e.getMessage()) == null ? "." : ": " + e.getMessage()));
            } catch (OutOfMemoryError e) {
                result = fail(String.format("Test for %s ran out of memory.", AtomicTest.this.getName()));
            } catch (StudentSecurityManager.ExitTrappedException e) {
                result = fail(String.format("Test for %s was stopped prematurely. Do not call System.exit().", AtomicTest.this.getName()));
            } catch (Exception e) {
                if (e instanceof SecurityException) {
                    checker.securityBreach(e.getMessage());
                }
                
                Writer stackTrace = new StringWriter();
                e.printStackTrace(new PrintWriter(stackTrace));
                result = fail(String.format("Exception for %s: %s", AtomicTest.this.getName(), e.toString()), stackTrace.toString());
            }
        }
    }
}
